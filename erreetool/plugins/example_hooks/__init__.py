"""
Example Hook Plugin - Demonstrates how to create lifecycle hooks.

Hooks allow plugins to execute code at specific points in the assessment lifecycle.
"""
from typing import Dict, Callable, Any
from erreetool.plugins import HookPlugin, PluginMetadata


class NotificationHooks(HookPlugin):
    """Example hooks for notifications and logging."""
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="notification-hooks",
            version="1.0.0",
            description="Notification hooks for assessment lifecycle events",
            author="ERREETOOL Team",
            license="MIT",
        )
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        self.webhook_url = config.get("webhook_url", "")
        self.slack_webhook = config.get("slack_webhook", "")
        return True
    
    def shutdown(self) -> None:
        pass
    
    def get_hooks(self) -> Dict[str, Callable]:
        return {
            "assessment_started": self.on_assessment_started,
            "assessment_completed": self.on_assessment_completed,
            "assessment_failed": self.on_assessment_failed,
            "high_signal_fact_found": self.on_high_signal_fact,
            "critical_vuln_found": self.on_critical_vuln,
            "skill_started": self.on_skill_started,
            "skill_completed": self.on_skill_completed,
            "tool_executed": self.on_tool_executed,
        }
    
    def on_assessment_started(self, target: str, goal: str, **kwargs) -> None:
        """Called when an assessment starts."""
        print(f"[HOOK] Assessment started for {target}: {goal}")
        if self.webhook_url:
            self._send_webhook("assessment_started", {
                "target": target,
                "goal": goal,
            })
    
    def on_assessment_completed(self, target: str, duration: float, facts_count: int, **kwargs) -> None:
        """Called when an assessment completes successfully."""
        print(f"[HOOK] Assessment completed for {target} in {duration:.1f}s ({facts_count} facts)")
        if self.webhook_url:
            self._send_webhook("assessment_completed", {
                "target": target,
                "duration": duration,
                "facts_count": facts_count,
            })
    
    def on_assessment_failed(self, target: str, error: str, **kwargs) -> None:
        """Called when an assessment fails."""
        print(f"[HOOK] Assessment failed for {target}: {error}")
        if self.webhook_url:
            self._send_webhook("assessment_failed", {
                "target": target,
                "error": error,
            })
    
    def on_high_signal_fact(self, fact: str, evidence_id: str, **kwargs) -> None:
        """Called when a high-signal fact is discovered."""
        print(f"[HOOK] High-signal fact: {fact} (evidence: {evidence_id})")
    
    def on_critical_vuln(self, vuln: str, target: str, evidence_id: str, **kwargs) -> None:
        """Called when a critical vulnerability is found."""
        print(f"[HOOK] CRITICAL VULNERABILITY on {target}: {vuln}")
        if self.slack_webhook:
            self._send_slack(f"🚨 *CRITICAL VULNERABILITY* on `{target}`: {vuln}")
    
    def on_skill_started(self, skill_name: str, target: str, **kwargs) -> None:
        """Called when a skill starts executing."""
        print(f"[HOOK] Skill started: {skill_name} on {target}")
    
    def on_skill_completed(self, skill_name: str, target: str, success: bool, **kwargs) -> None:
        """Called when a skill completes."""
        status = "success" if success else "failed"
        print(f"[HOOK] Skill {status}: {skill_name} on {target}")
    
    def on_tool_executed(self, tool_name: str, target: str, success: bool, duration: float, **kwargs) -> None:
        """Called when a tool finishes executing."""
        status = "OK" if success else "FAIL"
        print(f"[HOOK] Tool {status}: {tool_name} on {target} ({duration:.1f}s)")
    
    def _send_webhook(self, event: str, data: Dict[str, Any]) -> None:
        """Send webhook notification (placeholder)."""
        # Implementation would use requests or httpx
        pass
    
    def _send_slack(self, message: str) -> None:
        """Send Slack notification (placeholder)."""
        pass


# Plugin entry point
def get_plugin() -> NotificationHooks:
    """Entry point for plugin loader."""
    return NotificationHooks()