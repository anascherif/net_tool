"""
Safety gates and human-in-the-loop approval system.

Classifies tool actions by risk level and enforces approval policies
before dangerous operations are executed. Prevents accidental damage
during penetration testing by requiring explicit confirmation for
destructive or potentially unstable actions.

Risk levels:
    SAFE       - Read-only operations (nmap scan, whatweb, nuclei, crypto)
    MODERATE   - Active enumeration with mild side effects (gobuster, dns brute)
    DANGEROUS  - Active exploitation/potent writes (sqlmap --dump, shell rm)
    CRITICAL   - Potentially destructive or irreversible (shell shutdown,
                 sqlmap --os-shell, masscan 0.0.0.0/0)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


console = Console()


class RiskLevel(str, Enum):
    """Risk classification for tool actions."""
    SAFE = "safe"
    MODERATE = "moderate"
    DANGEROUS = "dangerous"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"safe": 0, "moderate": 1, "dangerous": 2, "critical": 3}[self.value]

    @property
    def color(self) -> str:
        return {
            "safe": "green",
            "moderate": "yellow",
            "dangerous": "red",
            "critical": "bright_red",
        }[self.value]


class ApprovalResponse(str, Enum):
    """User response to an approval prompt."""
    APPROVE = "approve"
    APPROVE_ALL = "approve_all"  # Approve this and all future same-risk prompts
    DENY = "deny"
    ABORT = "abort"  # Stop the whole assessment


@dataclass
class SafetyPolicy:
    """Configurable safety policy for the agent."""
    # Maximum risk level allowed without prompting the user
    auto_approve_below: RiskLevel = RiskLevel.MODERATE
    # Always prompt for these regardless of policy (deny by default)
    always_prompt: set[RiskLevel] = field(default_factory=lambda: {RiskLevel.CRITICAL})
    # Tool allow-list (bypass classification for these)
    trusted_tools: set[str] = field(default_factory=lambda: {
        "nmap", "whatweb", "nuclei", "crypto", "dns", "ping",
    })
    # Tool deny-list (never allowed)
    blocked_tools: set[str] = field(default_factory=set)
    # Flag: if True, never prompt - auto-approve SAFE/MODERATE, auto-deny DANGEROUS+
    non_interactive: bool = False
    # Auto-approvals granted during this session (for "approve_all" responses)
    _auto_approved: set[RiskLevel] = field(default_factory=set)

    def is_allowed(self, risk: RiskLevel) -> bool:
        """Check if a risk level is allowed under this policy."""
        if risk in self.always_prompt:
            return False
        if risk.rank <= self.auto_approve_below.rank:
            return True
        if risk in self._auto_approved:
            return True
        return False


@dataclass
class ActionClassification:
    """The result of classifying a tool action."""
    tool: str
    risk: RiskLevel
    reason: str
    dangerous_patterns: list[str] = field(default_factory=list)


# --- Danger heuristics ----------------------------------------------------

# Patterns in command arguments that bump risk to DANGEROUS
_DANGEROUS_ARG_PATTERNS = [
    (r"(?i)\b--dump\b", "sqlmap data dump"),
    (r"(?i)\b--os-shell\b", "OS shell access via sqlmap"),
    (r"(?i)\b--os-pwn\b", "OS pwn via sqlmap"),
    (r"(?i)\b--priv-esc\b", "privilege escalation attempt"),
    (r"(?i)\brm\s+-rf?\b", "recursive file delete"),
    (r"(?i)\bmkfs\b", "filesystem format"),
    (r"(?i)\bdd\s+if=", "raw disk write"),
    (r"(?i)\bshutdown\b", "system shutdown"),
    (r"(?i)\breboot\b", "system reboot"),
    (r"(?i)\bhalt\b", "system halt"),
    (r"(?i)\b:(){:\|:&};:", "fork bomb"),
    (r"(?i)\bcrontab\s+-r\b", "cron removal"),
    (r"(?i)\busermod\b", "user modification"),
    (r"(?i)\buseradd\b", "user creation"),
    (r"(?i)\bpasswd\s+\w+", "password change"),
    (r"(?i)\breg\s+delete\b", "registry deletion"),
    (r"(?i)\bDROP\s+TABLE\b", "SQL DROP TABLE"),
    (r"(?i)\bDELETE\s+FROM\b", "SQL DELETE FROM"),
]

# Patterns that bump risk to CRITICAL
_CRITICAL_PATTERNS = [
    (r"(?i)\b0\.0\.0\.0/0\b", "scan the entire internet"),
    (r"(?i)\b255\.255\.255\.255\b", "broadcast address"),
    (r"(?i)\b--os-pwn\b.*\b--priv-esc\b", "os-pwn with priv-esc"),
    (r"(?i)\bformat\s+c:", "format C drive"),
    (r"(?i)\bdiskpart\b.*\bclean\b", "diskpart clean (wipes disk)"),
    (r"(?i)\breg\s+add\\.*\\Run\b", "persistence via registry Run key"),
]

# Tools that are inherently MODERATE (active but not destructive)
_MODERATE_TOOLS = {
    "gobuster", "feroxbuster", "sqlmap", "shell",
}


def classify_action(tool: str, args: dict) -> ActionClassification:
    """Classify a tool action by risk level.

    Args:
        tool: Tool name (e.g., "nmap", "sqlmap", "shell")
        args: Tool arguments dict

    Returns:
        ActionClassification with risk level and reasoning
    """
    if tool in ("nmap", "whatweb", "nuclei", "crypto", "dns", "ping", "trace"):
        # Read-only tools - base is SAFE unless dangerous args
        risk = RiskLevel.SAFE
        reason = f"{tool} is read-only by default"
    elif tool in _MODERATE_TOOLS:
        risk = RiskLevel.MODERATE
        reason = f"{tool} performs active enumeration"
    else:
        risk = RiskLevel.MODERATE
        reason = f"unknown tool, treating as moderate"

    # String representation of all args for pattern matching
    args_str = " ".join(str(v) for v in _flatten_args(args))

    dangerous_matches: list[str] = []

    # Check critical patterns first
    for pattern, label in _CRITICAL_PATTERNS:
        if re.search(pattern, args_str):
            risk = RiskLevel.CRITICAL
            dangerous_matches.append(label)
            reason = f"Critical: {label}"

    # Then dangerous patterns (only if not already critical)
    if risk != RiskLevel.CRITICAL:
        for pattern, label in _DANGEROUS_ARG_PATTERNS:
            if re.search(pattern, args_str):
                if risk.rank < RiskLevel.DANGEROUS.rank:
                    risk = RiskLevel.DANGEROUS
                dangerous_matches.append(label)
                reason = f"Dangerous: {', '.join(dangerous_matches)}"

    # Shell commands get extra scrutiny
    if tool == "shell" and risk == RiskLevel.MODERATE:
        cmd = args.get("command", "")
        if any(p in cmd.lower() for p in ["curl", "wget", "nc ", "ncat", "python", "perl"]):
            risk = RiskLevel.DANGEROUS
            reason = "shell command uses network scripting tool"
            dangerous_matches.append("network scripting tool")

    return ActionClassification(
        tool=tool,
        risk=risk,
        reason=reason,
        dangerous_patterns=dangerous_matches,
    )


def _flatten_args(args: dict) -> list:
    """Flatten nested dict/list args into a list of strings."""
    out = []
    for v in args.values():
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            out.extend(_flatten_args(v))
        elif isinstance(v, (list, tuple)):
            for item in v:
                out.append(str(item))
        else:
            out.append(str(v))
    return out


# --- Approval prompt -------------------------------------------------------

class ApprovalPrompt:
    """Interactive approval prompt for risky actions."""

    def __init__(self, policy: SafetyPolicy):
        self.policy = policy

    def request(
        self,
        classification: ActionClassification,
        prompt_fn: Optional[Callable[[str], str]] = None,
    ) -> ApprovalResponse:
        """Request user approval for an action.

        Args:
            classification: The classified action
            prompt_fn: Optional function for getting user input (for testing)
                      Default uses console input

        Returns:
            ApprovalResponse indicating user's decision
        """
        # Check policy first
        if self.policy.is_allowed(classification.risk):
            return ApprovalResponse.APPROVE

        # Non-interactive mode: auto-deny
        if self.policy.non_interactive:
            console.print(
                f"[{classification.risk.color}]BLOCKED[/{classification.risk.color}] "
                f"{classification.tool} (non-interactive mode): {classification.reason}"
            )
            return ApprovalResponse.DENY

        # Display the action details
        self._display_action(classification)

        # Get user input
        if prompt_fn is None:
            prompt_fn = self._read_input

        while True:
            response = prompt_fn(
                f"[bold]Approve {classification.risk.value.upper()} action? "
                "(y)es/(n)o/(a)ll/(q)uit: [/bold]"
            ).strip().lower()

            if response in ("y", "yes", "approve", ""):
                return ApprovalResponse.APPROVE
            elif response in ("a", "all", "always"):
                self.policy._auto_approved.add(classification.risk)
                return ApprovalResponse.APPROVE_ALL
            elif response in ("q", "quit", "abort", "stop"):
                return ApprovalResponse.ABORT
            elif response in ("n", "no", "deny"):
                return ApprovalResponse.DENY
            else:
                console.print("[yellow]Please answer y/n/a/q[/yellow]")

    def _display_action(self, classification: ActionClassification):
        """Display the action that needs approval."""
        lines = [
            f"[bold]Tool:[/bold] {classification.tool}",
            f"[bold]Risk:[/bold] [{classification.risk.color}]"
            f"{classification.risk.value.upper()}[/{classification.risk.color}]",
            f"[bold]Reason:[/bold] {classification.reason}",
        ]
        if classification.dangerous_patterns:
            lines.append(
                f"[bold]Flags:[/bold] {', '.join(classification.dangerous_patterns)}"
            )
        console.print(Panel(
            "\n".join(lines),
            title="[bold red]APPROVAL REQUIRED[/bold red]",
            border_style=classification.risk.color,
        ))

    def _read_input(self, prompt: str) -> str:
        """Read user input from console."""
        return console.input(prompt)


# --- Main safety gate ------------------------------------------------------

class SafetyGate:
    """Safety gate that wraps tool execution with risk-based approval."""

    def __init__(self, policy: Optional[SafetyPolicy] = None):
        self.policy = policy or SafetyPolicy()
        self.prompt = ApprovalPrompt(self.policy)
        # Track approvals/denials for reporting
        self.history: list[dict] = []

    def check(
        self,
        tool: str,
        args: dict,
        prompt_fn: Optional[Callable[[str], str]] = None,
    ) -> tuple[bool, ActionClassification, Optional[ApprovalResponse]]:
        """Check if an action is allowed.

        Returns:
            (allowed, classification, response) tuple.
            - allowed: True if the action should proceed
            - classification: The ActionClassification
            - response: The user's response (None if auto-approved)
        """
        # Hard block list
        if tool in self.policy.blocked_tools:
            classification = ActionClassification(
                tool=tool,
                risk=RiskLevel.CRITICAL,
                reason="Tool is on the blocked list",
            )
            self.history.append({
                "tool": tool, "args": args, "allowed": False,
                "reason": "blocked tool", "risk": "blocked",
            })
            return False, classification, None

        # Classify
        classification = classify_action(tool, args)
        response = None

        # Check against policy
        if self.policy.is_allowed(classification.risk):
            allowed = True
        else:
            # Need user approval
            response = self.prompt.request(classification, prompt_fn=prompt_fn)
            if response == ApprovalResponse.ABORT:
                allowed = False
            elif response in (ApprovalResponse.APPROVE, ApprovalResponse.APPROVE_ALL):
                allowed = True
            else:  # DENY
                allowed = False

        self.history.append({
            "tool": tool,
            "args": args,
            "allowed": allowed,
            "risk": classification.risk.value,
            "reason": classification.reason,
            "response": response.value if response else "auto",
        })

        return allowed, classification, response

    def should_abort(self) -> bool:
        """Check if the user requested to abort the whole assessment."""
        return any(
            h.get("response") == ApprovalResponse.ABORT.value
            for h in self.history
        )

    def summary(self) -> dict:
        """Get summary of all safety decisions."""
        approved = sum(1 for h in self.history if h["allowed"])
        denied = sum(1 for h in self.history if not h["allowed"])
        return {
            "total_actions": len(self.history),
            "approved": approved,
            "denied": denied,
            "by_risk": {
                risk: sum(1 for h in self.history if h["risk"] == risk)
                for risk in ("safe", "moderate", "dangerous", "critical")
            },
        }
