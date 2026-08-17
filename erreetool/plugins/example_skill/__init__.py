"""
Example Skill Plugin - Demonstrates how to create a custom skill plugin.

This plugin adds a 'whois-enumeration' skill for domain information gathering.
"""
from erreetool.plugins import SkillPlugin, PluginMetadata


class WhoisEnumerationPlugin(SkillPlugin):
    """WHOIS enumeration skill plugin."""
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="whois-enumeration-skill",
            version="1.0.0",
            description="WHOIS-based domain enumeration and registration analysis",
            author="ERREETOOL Team",
            license="MIT",
        )
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        return True
    
    def shutdown(self) -> None:
        pass
    
    def get_skill_name(self) -> str:
        return "whois-enumeration"
    
    def get_skill_definition(self) -> Dict[str, Any]:
        return {
            "name": "whois-enumeration",
            "description": "Enumerate domain registration details via WHOIS",
            "tags": ["whois", "domain", "enum", "recon"],
            "author": "ERREETOOL Team",
            "version": "1.0",
            "requires_tools": ["whois"],
            
            "phases": [
                {
                    "name": "whois_lookup",
                    "description": "Perform WHOIS lookup on target domain",
                    "condition": "True",
                    "steps": [
                        {
                            "name": "whois_query",
                            "tool": "whois",
                            "args": {
                                "target": "{target}"
                            },
                            "save_as": "whois_output",
                            "description": "Query WHOIS for domain registration info",
                            "on_error": "abort",
                            "extract_facts": [
                                {
                                    "pattern": "Registrar:\\s*(.+)",
                                    "fact": "Registrar: {1}",
                                    "type": "high_signal"
                                },
                                {
                                    "pattern": "Creation Date:\\s*(.+)",
                                    "fact": "Domain created: {1}",
                                    "type": "high_signal"
                                },
                                {
                                    "pattern": "Expiration Date:\\s*(.+)",
                                    "fact": "Domain expires: {1}",
                                    "type": "high_signal"
                                },
                                {
                                    "pattern": "Name Server:\\s*(.+)",
                                    "fact": "Name server: {1}",
                                    "type": "high_signal"
                                },
                                {
                                    "pattern": "Status:\\s*(.+)",
                                    "fact": "Domain status: {1}",
                                    "type": "high_signal"
                                },
                            ]
                        }
                    ]
                },
                {
                    "name": "analyze_results",
                    "description": "Analyze WHOIS results for security insights",
                    "condition": "fact_count('Registrar') > 0",
                    "steps": [
                        {
                            "name": "check_privacy",
                            "tool": "shell",
                            "args": {
                                "command": "echo 'Analyzing WHOIS privacy protection...'"
                            },
                            "save_as": "privacy_check",
                            "description": "Check for privacy protection services",
                            "on_error": "continue",
                            "extract_facts": [
                                {
                                    "pattern": "Privacy|Proxy|Protected",
                                    "fact": "WHOIS privacy protection detected",
                                    "type": "high_signal"
                                }
                            ]
                        }
                    ]
                }
            ],
            
            "gates": [
                {
                    "name": "whois_data",
                    "condition": "fact_count('Registrar') > 0 OR fact_count('Creation Date') > 0",
                    "on_fail": "No WHOIS data retrieved",
                    "severity": "error"
                }
            ]
        }


# Plugin entry point
def get_plugin() -> WhoisEnumerationPlugin:
    """Entry point for plugin loader."""
    return WhoisEnumerationPlugin()