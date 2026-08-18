"""
API Routes - REST endpoints for the ERREETOOL API server.
"""

import asyncio
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import FileResponse

from erreetool.agent.loop import AgentConfig, AgentLoop
from erreetool.agent.providers import MultiProvider
from erreetool.agent.skills import skill_registry
from erreetool.agent.state import AgentState
from erreetool.api.auth import (
    UserInDB,
    create_access_token,
    get_current_user,
    get_password_hash,
    verify_password,
    create_user,
)
from erreetool.api.models import (
    AssessmentRequest,
    AssessmentResponse,
    AssessmentResult,
    AssessmentStatusEnum,
    AssessmentStatusResponse,
    BulkAssessmentRequest,
    CampaignListResponse,
    CampaignRequest,
    CampaignResponse,
    HealthResponse,
    SkillInfo,
    SkillListResponse,
    SkillRequest,
    Token,
    UserCreate,
    UserResponse,
)
from erreetool.config import (
    OPENROUTER_API_KEY,
)
from erreetool.reporting.generator import ReportGenerator

router = APIRouter()

# In-memory storage (replace with database in production)
_assessments: dict[str, dict] = {}
_campaigns: dict[str, dict] = {}
_assessment_tasks: dict[str, asyncio.Task] = {}


# ===== Health Check =====


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.utcnow(),
        services={
            "api": "running",
            "database": "memory",
            "llm": "configured" if OPENROUTER_API_KEY else "not_configured",
        },
    )


# ===== Authentication =====


@router.post("/auth/login", response_model=Token)
async def login(username: str, password: str):
    """Login and get access token."""
    user = get_current_user(username)
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user",
        )

    # Update last login
    user.last_login = datetime.utcnow()

    access_token = create_access_token(
        data={"sub": user.username, "user_id": user.id, "role": user.role}
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/auth/register", response_model=UserResponse)
async def register(
    user_data: UserCreate,
    current_user: UserInDB = Depends(require_permission("admin:create")),
):
    """Register a new user (admin only)."""
    if get_current_user(user_data.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )

    user = create_user(
        username=user_data.username,
        email=user_data.email,
        password=user_data.password,
        full_name=user_data.full_name,
        role=user_data.role,
    )

    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        last_login=user.last_login,
    )


@router.get("/auth/me", response_model=UserResponse)
async def get_me(
    current_user: UserInDB = Depends(require_permission("assessment:read")),
):
    """Get current user info."""
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
        last_login=current_user.last_login,
    )


# ===== Assessments =====


async def _run_assessment_background(assessment_id: str, request: AssessmentRequest):
    """Background task to run assessment."""
    assessment = _assessments[assessment_id]
    assessment["status"] = AssessmentStatusEnum.RUNNING
    assessment["updated_at"] = datetime.utcnow()
    assessment["started_at"] = datetime.utcnow()

    try:
        # Initialize state
        state = AgentState()
        state.context.target = request.target
        state.context.goals.append(
            request.goal or f"Penetration test on {request.target}"
        )

        # Get LLM provider
        provider = None
        if not request.offline:
            try:
                provider = MultiProvider.from_env()
            except ValueError:
                pass  # Continue without LLM

        # Configure agent
        config = AgentConfig(
            max_steps=request.max_steps,
            evidence_gate_required=not request.offline,
            show_reasoning=False,
            auto_report=True,
            skill_mode=request.skill is not None,
            skill_names=request.skill or "",
            skill_mode_type=request.skill_mode.value,
            use_memory=request.use_memory,
            use_safety_gate=request.use_safety_gate,
            non_interactive=request.non_interactive,
            allow_exploitation=request.allow_exploitation,
            human_in_loop=request.human_in_loop,
        )

        loop = AgentLoop(state, provider, config) if provider or request.skill else None

        if loop:
            final_state = loop.run(request.goal)
        else:
            # Offline mode
            final_state = _run_offline_assessment(state, request.target, request.quick)

        # Generate report
        generator = ReportGenerator()
        report_path = generator.generate(final_state, format="markdown")

        # Update assessment
        assessment["status"] = AssessmentStatusEnum.COMPLETED
        assessment["completed_at"] = datetime.utcnow()
        assessment["report_path"] = report_path
        assessment["high_signal_facts"] = final_state.context.high_signal_facts
        assessment["evidence_count"] = len(final_state.evidence_log)
        assessment["steps_completed"] = len(
            [s for s in final_state.steps if s.status.value == "completed"]
        )
        assessment["duration_seconds"] = (
            assessment["completed_at"] - assessment["started_at"]
        ).total_seconds()

    except Exception as e:
        assessment["status"] = AssessmentStatusEnum.FAILED
        assessment["error"] = str(e)
        assessment["completed_at"] = datetime.utcnow()

    assessment["updated_at"] = datetime.utcnow()


def _run_offline_assessment(state: AgentState, target: str, quick: bool) -> AgentState:
    """Run basic assessment without LLM."""
    from erreetool.agent.tools import tool_registry

    # Run nmap
    nmap = tool_registry.get("nmap")
    if nmap and nmap.is_available():
        result = nmap.run(target=target, ports="top-100" if quick else "top-1000")
        if result.success:
            state.add_evidence(
                "tool_output",
                "nmap",
                result.output,
                {"command": result.command, "duration": result.duration},
            )
            _extract_nmap_facts(state, result.output)

    # Run nuclei
    nuclei = tool_registry.get("nuclei")
    if nuclei and nuclei.is_available():
        result = nuclei.run(target=target, severity="critical,high" if quick else None)
        if result.success:
            state.add_evidence(
                "tool_output",
                "nuclei",
                result.output,
                {"command": result.command, "duration": result.duration},
            )
            _extract_nuclei_facts(state, result.output)

    state.context.current_phase = "complete"
    state.save()
    return state


def _extract_nmap_facts(state: AgentState, output: str):
    import re

    for match in re.finditer(r"(\d+)/tcp\s+open\s+(\S+)", output):
        port, service = match.groups()
        state.add_high_signal_fact(f"Port {port}/tcp open: {service}")


def _extract_nuclei_facts(state: AgentState, output: str):
    import re

    for match in re.finditer(r"CVE-\d{4}-\d{4,7}", output):
        state.add_high_signal_fact(f"Vulnerability: {match.group()}")


@router.post(
    "/assessments",
    response_model=AssessmentResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_assessment(
    request: AssessmentRequest,
    background_tasks: BackgroundTasks,
    current_user: UserInDB = Depends(require_permission("assessment:create")),
):
    """Create and start a new assessment."""
    assessment_id = str(uuid.uuid4())

    assessment = {
        "assessment_id": assessment_id,
        "target": request.target,
        "goal": request.goal,
        "status": AssessmentStatusEnum.PENDING,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "created_by": current_user.username,
        "request": request.model_dump(),
    }

    _assessments[assessment_id] = assessment

    # Start background task
    task = asyncio.create_task(_run_assessment_background(assessment_id, request))
    _assessment_tasks[assessment_id] = task

    return AssessmentResponse(
        assessment_id=assessment_id,
        status=AssessmentStatusEnum.PENDING,
        message="Assessment queued for execution",
        created_at=assessment["created_at"],
        target=request.target,
    )


@router.get("/assessments", response_model=list[AssessmentStatusResponse])
async def list_assessments(
    status_filter: AssessmentStatusEnum | None = None,
    limit: int = 50,
    offset: int = 0,
    current_user: UserInDB = Depends(require_permission("assessment:list")),
):
    """List all assessments."""
    assessments = list(_assessments.values())

    if status_filter:
        assessments = [a for a in assessments if a["status"] == status_filter]

    assessments.sort(key=lambda x: x["created_at"], reverse=True)
    assessments = assessments[offset : offset + limit]

    return [
        AssessmentStatusResponse(
            assessment_id=a["assessment_id"],
            status=a["status"],
            target=a["target"],
            goal=a.get("goal"),
            created_at=a["created_at"],
            updated_at=a["updated_at"],
            progress=1.0
            if a["status"] == AssessmentStatusEnum.COMPLETED
            else 0.5
            if a["status"] == AssessmentStatusEnum.RUNNING
            else 0.0,
            steps_completed=a.get("steps_completed", 0),
            total_steps=a.get("request", {}).get("max_steps", 30),
            high_signal_facts=a.get("high_signal_facts", []),
            evidence_count=a.get("evidence_count", 0),
            report_path=a.get("report_path"),
            error=a.get("error"),
        )
        for a in assessments
    ]


@router.get("/assessments/{assessment_id}", response_model=AssessmentStatusResponse)
async def get_assessment(
    assessment_id: str,
    current_user: UserInDB = Depends(require_permission("assessment:read")),
):
    """Get assessment status."""
    assessment = _assessments.get(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    return AssessmentStatusResponse(
        assessment_id=assessment["assessment_id"],
        status=assessment["status"],
        target=assessment["target"],
        goal=assessment.get("goal"),
        created_at=assessment["created_at"],
        updated_at=assessment["updated_at"],
        progress=1.0
        if assessment["status"] == AssessmentStatusEnum.COMPLETED
        else 0.5
        if assessment["status"] == AssessmentStatusEnum.RUNNING
        else 0.0,
        steps_completed=assessment.get("steps_completed", 0),
        total_steps=assessment.get("request", {}).get("max_steps", 30),
        high_signal_facts=assessment.get("high_signal_facts", []),
        evidence_count=assessment.get("evidence_count", 0),
        report_path=assessment.get("report_path"),
        error=assessment.get("error"),
    )


@router.get("/assessments/{assessment_id}/report")
async def get_assessment_report(
    assessment_id: str,
    format: str = "markdown",
    current_user: UserInDB = Depends(require_permission("assessment:read")),
):
    """Download assessment report."""
    assessment = _assessments.get(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    report_path = assessment.get("report_path")
    if not report_path or not Path(report_path).exists():
        raise HTTPException(status_code=404, detail="Report not found")

    if format == "markdown":
        return FileResponse(
            report_path,
            media_type="text/markdown",
            filename=f"report_{assessment_id}.md",
        )
    elif format == "json":
        with open(report_path, "r") as f:
            content = f.read()
        return {"content": content, "format": "markdown"}
    else:
        raise HTTPException(
            status_code=400, detail="Invalid format. Use 'markdown' or 'json'"
        )


@router.get("/assessments/{assessment_id}/result", response_model=AssessmentResult)
async def get_assessment_result(
    assessment_id: str,
    current_user: UserInDB = Depends(require_permission("assessment:read")),
):
    """Get detailed assessment result."""
    assessment = _assessments.get(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    if assessment["status"] != AssessmentStatusEnum.COMPLETED:
        raise HTTPException(status_code=400, detail="Assessment not completed")

    return AssessmentResult(
        assessment_id=assessment_id,
        target=assessment["target"],
        summary={
            "high_signal_facts": len(assessment.get("high_signal_facts", [])),
            "evidence_count": assessment.get("evidence_count", 0),
            "duration_seconds": assessment.get("duration_seconds", 0),
        },
        high_signal_facts=assessment.get("high_signal_facts", []),
        mitre_techniques=[],  # Would need to parse from report
        attack_paths=[],
        report_path=assessment.get("report_path"),
        duration_seconds=assessment.get("duration_seconds", 0),
        completed_at=assessment["completed_at"],
    )


@router.delete("/assessments/{assessment_id}")
async def cancel_assessment(
    assessment_id: str,
    current_user: UserInDB = Depends(require_permission("assessment:create")),
):
    """Cancel a running assessment."""
    assessment = _assessments.get(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    if assessment["status"] in [
        AssessmentStatusEnum.COMPLETED,
        AssessmentStatusEnum.FAILED,
        AssessmentStatusEnum.CANCELLED,
    ]:
        raise HTTPException(status_code=400, detail="Assessment already finished")

    # Cancel background task
    task = _assessment_tasks.get(assessment_id)
    if task and not task.done():
        task.cancel()

    assessment["status"] = AssessmentStatusEnum.CANCELLED
    assessment["updated_at"] = datetime.utcnow()

    return {"message": "Assessment cancelled"}


@router.post("/assessments/bulk", response_model=list[AssessmentResponse])
async def create_bulk_assessments(
    request: BulkAssessmentRequest,
    background_tasks: BackgroundTasks,
    current_user: UserInDB = Depends(require_permission("assessment:create")),
):
    """Create multiple assessments for multiple targets."""
    responses = []

    for target in request.targets:
        assessment_request = AssessmentRequest(
            target=target,
            goal=request.goal,
            quick=request.quick,
            skill=request.skill,
            skill_mode=request.skill_mode,
            max_steps=request.max_steps,
        )

        assessment_id = str(uuid.uuid4())
        assessment = {
            "assessment_id": assessment_id,
            "target": target,
            "goal": request.goal,
            "status": AssessmentStatusEnum.PENDING,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "created_by": current_user.username,
            "request": assessment_request.model_dump(),
        }

        _assessments[assessment_id] = assessment

        task = asyncio.create_task(
            _run_assessment_background(assessment_id, assessment_request)
        )
        _assessment_tasks[assessment_id] = task

        responses.append(
            AssessmentResponse(
                assessment_id=assessment_id,
                status=AssessmentStatusEnum.PENDING,
                message="Assessment queued for execution",
                created_at=assessment["created_at"],
                target=target,
            )
        )

    return responses


# ===== Campaigns =====


@router.post(
    "/campaigns", response_model=CampaignResponse, status_code=status.HTTP_201_CREATED
)
async def create_campaign(
    request: CampaignRequest,
    current_user: UserInDB = Depends(require_permission("campaign:create")),
):
    """Create a new campaign."""
    campaign_id = str(uuid.uuid4())

    campaign = {
        "campaign_id": campaign_id,
        "name": request.name,
        "description": request.description,
        "targets": request.targets,
        "goal": request.goal,
        "schedule": request.schedule,
        "skill_mode": request.skill_mode,
        "max_steps": request.max_steps,
        "enabled": request.enabled,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "created_by": current_user.username,
        "total_assessments": 0,
        "completed_assessments": 0,
        "status": "created",
    }

    _campaigns[campaign_id] = campaign

    return CampaignResponse(**campaign)


@router.get("/campaigns", response_model=CampaignListResponse)
async def list_campaigns(
    current_user: UserInDB = Depends(require_permission("campaign:list")),
):
    """List all campaigns."""
    campaigns = list(_campaigns.values())
    campaigns.sort(key=lambda x: x["created_at"], reverse=True)

    return CampaignListResponse(
        campaigns=[CampaignResponse(**c) for c in campaigns],
        total=len(campaigns),
    )


@router.get("/campaigns/{campaign_id}", response_model=CampaignResponse)
async def get_campaign(
    campaign_id: str,
    current_user: UserInDB = Depends(require_permission("campaign:read")),
):
    """Get campaign details."""
    campaign = _campaigns.get(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    return CampaignResponse(**campaign)


@router.post("/campaigns/{campaign_id}/run")
async def run_campaign(
    campaign_id: str,
    background_tasks: BackgroundTasks,
    target: str | None = None,
    current_user: UserInDB = Depends(require_permission("campaign:update")),
):
    """Run a campaign (all targets or single target)."""
    campaign = _campaigns.get(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    targets = [target] if target else campaign["targets"]

    # Update campaign status
    campaign["status"] = "running"
    campaign["updated_at"] = datetime.utcnow()
    campaign["total_assessments"] = len(targets)
    campaign["completed_assessments"] = 0

    assessment_ids = []

    for t in targets:
        assessment_request = AssessmentRequest(
            target=t,
            goal=campaign.get("goal"),
            skill_mode=campaign["skill_mode"],
            max_steps=campaign["max_steps"],
        )

        assessment_id = str(uuid.uuid4())
        assessment = {
            "assessment_id": assessment_id,
            "target": t,
            "goal": campaign.get("goal"),
            "status": AssessmentStatusEnum.PENDING,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "created_by": current_user.username,
            "request": assessment_request.model_dump(),
            "campaign_id": campaign_id,
        }

        _assessments[assessment_id] = assessment
        assessment_ids.append(assessment_id)

        task = asyncio.create_task(
            _run_assessment_background(assessment_id, assessment_request)
        )
        _assessment_tasks[assessment_id] = task

    return {
        "message": f"Campaign started with {len(targets)} assessments",
        "campaign_id": campaign_id,
        "assessment_ids": assessment_ids,
    }


# ===== Skills =====


@router.get("/skills", response_model=SkillListResponse)
async def list_skills(
    tag: str | None = None,
    current_user: UserInDB = Depends(require_permission("skill:list")),
):
    """List available skills."""
    skills = skill_registry.list_skills()

    if tag:
        skills = [s for s in skills if tag in s.tags]

    return SkillListResponse(
        skills=[
            SkillInfo(
                name=s.name,
                description=s.description,
                tags=s.tags,
                author=s.author,
                version=s.version,
                requires_tools=s.requires_tools,
                phases=len(s.phases),
                gates=len(s.gates),
            )
            for s in skills
        ],
        total=len(skills),
    )


@router.get("/skills/{skill_name}", response_model=SkillInfo)
async def get_skill(
    skill_name: str,
    current_user: UserInDB = Depends(require_permission("skill:read")),
):
    """Get skill details."""
    skill = skill_registry.get_skill(skill_name)
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")

    return SkillInfo(
        name=skill.name,
        description=skill.description,
        tags=skill.tags,
        author=skill.author,
        version=skill.version,
        requires_tools=skill.requires_tools,
        phases=len(skill.phases),
        gates=len(skill.gates),
    )


@router.post("/skills/execute")
async def execute_skill(
    request: SkillRequest,
    current_user: UserInDB = Depends(require_permission("skill:execute")),
):
    """Execute a specific skill on a target."""
    skill = skill_registry.get_skill(request.name)
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")

    # Run skill
    state = AgentState()
    state.context.target = request.target
    state.context.goals.append(f"Execute skill {request.name} on {request.target}")

    from erreetool.agent.skills import SkillExecutor

    executor = SkillExecutor(state)
    result = executor.execute(skill)

    return {
        "success": result.success,
        "phases_executed": result.phases_executed,
        "phases_skipped": result.phases_skipped,
        "steps_executed": result.steps_executed,
        "steps_failed": result.steps_failed,
        "facts_extracted": result.facts_extracted,
        "gates_passed": result.gates_passed,
        "gates_failed": result.gates_failed,
        "duration": result.duration,
        "high_signal_facts": state.context.high_signal_facts,
    }


# ===== Memory =====


@router.get("/memory/sessions")
async def list_memory_sessions(
    target: str | None = None,
    limit: int = 20,
    current_user: UserInDB = Depends(require_permission("memory:list")),
):
    """List stored memory sessions."""
    from erreetool.agent.memory import memory_store

    memory_store.load()

    sessions = list(memory_store._sessions.values())

    if target:
        sessions = [s for s in sessions if s.target == target]

    sessions.sort(key=lambda x: x.timestamp, reverse=True)
    sessions = sessions[:limit]

    return {
        "sessions": [
            {
                "session_id": s.session_id,
                "target": s.target,
                "timestamp": s.timestamp,
                "duration": s.duration,
                "skills_run": s.skills_run,
                "tools_used": s.tools_used,
                "high_signal_facts": len(s.high_signal_facts),
                "critical_findings": len(s.critical_findings),
                "high_findings": len(s.high_findings),
                "success": s.success,
            }
            for s in sessions
        ],
        "total": len(sessions),
    }


@router.get("/memory/patterns")
async def list_finding_patterns(
    pattern_type: str | None = None,
    current_user: UserInDB = Depends(require_permission("memory:read")),
):
    """List finding patterns from memory."""
    from erreetool.agent.memory import memory_store

    memory_store.load()

    patterns = list(memory_store._patterns.values())

    if pattern_type:
        patterns = [p for p in patterns if p.pattern_type == pattern_type]

    return {
        "patterns": [
            {
                "pattern_id": p.pattern_id,
                "pattern_type": p.pattern_type,
                "description": p.description,
                "indicators": p.indicators,
                "seen_count": p.seen_count,
                "confidence": p.confidence.value,
                "tags": p.tags,
            }
            for p in patterns
        ],
        "total": len(patterns),
    }


# ===== Doctor/Diagnostics =====


@router.get("/doctor")
async def run_doctor(
    current_user: UserInDB = Depends(require_permission("assessment:read")),
):
    """Run diagnostic health check."""
    import io
    from contextlib import redirect_stdout

    from erreetool.commands.doctor import run as doctor_run

    # Capture doctor output
    f = io.StringIO()
    with redirect_stdout(f):
        try:
            doctor_run(json_output=True)
        except Exception:
            pass
    output = f.getvalue()

    return {"output": output}


# ===== Export OpenAPI =====


@router.get("/openapi.json")
async def get_openapi():
    """Get OpenAPI schema."""
    from fastapi.openapi.utils import get_openapi

    from erreetool.api.server import app

    return get_openapi(
        title="ERREETOOL API",
        version="1.0.0",
        description="REST API for ERREETOOL penetration testing toolkit",
        routes=app.routes,
    )


# Global for access in openapi endpoint
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7
