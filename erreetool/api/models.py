"""
API Models - Pydantic models for request/response validation.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, HttpUrl
from enum import Enum


class AssessmentStatusEnum(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SkillModeEnum(str, Enum):
    AUTO = "auto"
    QUICK = "quick"
    FULL = "full"


class AssessmentRequest(BaseModel):
    target: str = Field(..., description="Target host or IP address")
    goal: Optional[str] = Field(None, description="Specific assessment goal")
    full: bool = Field(False, description="Full assessment (all tools, deep scan)")
    quick: bool = Field(False, description="Quick assessment (essential tools only)")
    offline: bool = Field(False, description="Offline mode - no LLM calls")
    max_steps: int = Field(30, ge=1, le=200, description="Maximum agent steps")
    skill: Optional[str] = Field(None, description="Run specific skill(s) by name (comma-separated)")
    skill_mode: SkillModeEnum = Field(SkillModeEnum.AUTO, description="Skill selection mode")
    use_memory: bool = Field(True, description="Load relevant past sessions")
    use_safety_gate: bool = Field(True, description="Enable safety gate for dangerous actions")
    non_interactive: bool = Field(True, description="Auto-deny dangerous actions (CI/CD mode)")
    allow_exploitation: bool = Field(False, description="Master switch for exploit verification")
    human_in_loop: bool = Field(False, description="Prompt before every tool call")


class AssessmentResponse(BaseModel):
    assessment_id: str
    status: AssessmentStatusEnum
    message: str
    created_at: datetime
    target: str


class AssessmentStatusResponse(BaseModel):
    assessment_id: str
    status: AssessmentStatusEnum
    target: str
    goal: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    progress: Optional[float] = None
    steps_completed: int = 0
    total_steps: int = 0
    high_signal_facts: List[str] = []
    evidence_count: int = 0
    report_path: Optional[str] = None
    error: Optional[str] = None


class CampaignRequest(BaseModel):
    name: str = Field(..., description="Campaign name")
    description: Optional[str] = Field(None, description="Campaign description")
    targets: List[str] = Field(..., description="List of target hosts/IPs")
    goal: Optional[str] = Field(None, description="Campaign goal")
    schedule: Optional[str] = Field(None, description="Cron expression for scheduled runs")
    skill_mode: SkillModeEnum = Field(SkillModeEnum.AUTO, description="Skill selection mode")
    max_steps: int = Field(50, ge=1, le=200)
    enabled: bool = Field(True, description="Whether campaign is active")


class CampaignResponse(BaseModel):
    campaign_id: str
    name: str
    description: Optional[str] = None
    targets: List[str]
    goal: Optional[str] = None
    schedule: Optional[str] = None
    skill_mode: SkillModeEnum
    max_steps: int
    enabled: bool
    created_at: datetime
    updated_at: datetime
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    status: str = "created"
    total_assessments: int = 0
    completed_assessments: int = 0


class CampaignListResponse(BaseModel):
    campaigns: List[CampaignResponse]
    total: int


class SkillRequest(BaseModel):
    name: str = Field(..., description="Skill name to execute")
    target: str = Field(..., description="Target for skill execution")
    args: Dict[str, Any] = Field(default_factory=dict, description="Additional arguments")


class SkillInfo(BaseModel):
    name: str
    description: str
    tags: List[str] = []
    author: str = ""
    version: str = "1.0"
    requires_tools: List[str] = []
    phases: int = 0
    gates: int = 0


class SkillListResponse(BaseModel):
    skills: List[SkillInfo]
    total: int


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str
    timestamp: datetime
    services: Dict[str, str] = {}


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., description="Email address")
    password: str = Field(..., min_length=8, max_length=100)
    full_name: Optional[str] = None
    role: str = Field("analyst", description="User role: admin, analyst, viewer")


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool = True
    created_at: datetime
    last_login: Optional[datetime] = None


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[str] = None
    role: Optional[str] = None


class AssessmentResult(BaseModel):
    assessment_id: str
    target: str
    summary: Dict[str, Any]
    high_signal_facts: List[str]
    mitre_techniques: List[Dict[str, Any]] = []
    attack_paths: List[Dict[str, Any]] = []
    report_path: Optional[str] = None
    duration_seconds: float
    completed_at: datetime


class CampaignRunRequest(BaseModel):
    campaign_id: str
    target: Optional[str] = Field(None, description="Override target for single run")


class BulkAssessmentRequest(BaseModel):
    targets: List[str] = Field(..., min_length=1)
    goal: Optional[str] = None
    quick: bool = False
    skill: Optional[str] = None
    skill_mode: SkillModeEnum = SkillModeEnum.AUTO
    max_steps: int = 30