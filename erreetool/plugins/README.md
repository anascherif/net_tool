# ERREETOOL Plugin System

ERREETOOL supports a plugin architecture that allows you to extend the toolkit with custom tools, skills, LLM providers, and lifecycle hooks without modifying the core codebase.

## Plugin Types

### 1. Tool Plugins
Add new security tools to the agent's toolbox.

```python
from erreetool.plugins import ToolPlugin, PluginMetadata
from erreetool.agent.tools.base import ToolWrapper, ToolResult

class MyCustomTool(ToolWrapper):
    name = "mytool"
    windows_binary = "mytool.exe"
    linux_binary = "mytool"
    
    def build_args(self, **kwargs):
        return [kwargs.get("target", "")]
    
    def is_available(self):
        # Check if tool binary exists
        return True
    
    def run(self, **kwargs):
        # Execute tool and return ToolResult
        pass

class MyToolPlugin(ToolPlugin):
    @property
    def metadata(self):
        return PluginMetadata(
            name="my-custom-tool",
            version="1.0.0",
            description="My custom security tool",
        )
    
    def get_tool_class(self):
        return MyCustomTool
    
    def get_tool_name(self):
        return "mytool"
```

### 2. Skill Plugins
Add new assessment skills (structured workflows).

```python
from erreetool.plugins import SkillPlugin, PluginMetadata

class MySkillPlugin(SkillPlugin):
    @property
    def metadata(self):
        return PluginMetadata(
            name="my-skill",
            version="1.0.0",
            description="My custom assessment skill",
        )
    
    def get_skill_name(self):
        return "my-skill"
    
    def get_skill_definition(self):
        return {
            "name": "my-skill",
            "description": "My custom skill",
            "tags": ["custom", "tag"],
            "requires_tools": ["nmap"],
            "phases": [...],
            "gates": [...],
        }
```

### 3. Provider Plugins
Add new LLM providers.

```python
from erreetool.plugins import ProviderPlugin, PluginMetadata
from erreetool.agent.providers import LLMProvider

class MyProvider(LLMProvider):
    # Implement LLMProvider interface
    pass

class MyProviderPlugin(ProviderPlugin):
    @property
    def metadata(self):
        return PluginMetadata(name="my-provider", version="1.0.0", ...)
    
    def get_provider_class(self):
        return MyProvider
    
    def get_provider_name(self):
        return "my-provider"
```

### 4. Hook Plugins
React to lifecycle events.

```python
from erreetool.plugins import HookPlugin, PluginMetadata

class MyHooksPlugin(HookPlugin):
    @property
    def metadata(self):
        return PluginMetadata(name="my-hooks", version="1.0.0", ...)
    
    def get_hooks(self):
        return {
            "assessment_started": self.on_start,
            "assessment_completed": self.on_complete,
            "high_signal_fact_found": self.on_fact,
            "critical_vuln_found": self.on_critical,
        }
    
    def on_start(self, target, goal, **kwargs):
        print(f"Starting assessment of {target}")
    
    def on_complete(self, target, duration, facts_count, **kwargs):
        print(f"Completed in {duration}s with {facts_count} facts")
    
    def on_fact(self, fact, evidence_id, **kwargs):
        print(f"New fact: {fact}")
    
    def on_critical(self, vuln, target, evidence_id, **kwargs):
        print(f"CRITICAL: {vuln} on {target}")
```

## Installation

### Local Development
Place plugin directories in:
- `~/.local/share/erreetool/plugins/` (Linux/macOS)
- `%APPDATA%\erreetool\plugins\` (Windows)
- `./plugins/` (project directory)

Each plugin should be a Python package with an `__init__.py` that exports a `get_plugin()` function.

### Package Distribution
Publish to PyPI with entry points in `pyproject.toml`:

```toml
[project.entry-points."erreetool.plugins"]
my-tool = "my_package.plugins:MyToolPlugin"
my-skill = "my_package.plugins:MySkillPlugin"
my-hooks = "my_package.plugins:MyHooksPlugin"
```

## Available Hooks

| Hook | Parameters | Description |
|------|------------|-------------|
| `assessment_started` | `target`, `goal` | Assessment begins |
| `assessment_completed` | `target`, `duration`, `facts_count` | Assessment finishes successfully |
| `assessment_failed` | `target`, `error` | Assessment fails |
| `high_signal_fact_found` | `fact`, `evidence_id` | New high-signal fact discovered |
| `critical_vuln_found` | `vuln`, `target`, `evidence_id` | Critical vulnerability found |
| `skill_started` | `skill_name`, `target` | Skill execution begins |
| `skill_completed` | `skill_name`, `target`, `success` | Skill execution ends |
| `tool_executed` | `tool_name`, `target`, `success`, `duration` | Tool finishes execution |

## Plugin Discovery

Plugins are automatically discovered from:
1. Entry points (`erreetool.plugins` group)
2. User plugin directory (`~/.local/share/erreetool/plugins/`)
3. Project plugin directory (`./plugins/`)
4. Additional directories added via `PluginManager.add_plugin_dir()`

## Configuration

Plugins can be configured via:
- Environment variables
- `ERREETOOL_PLUGIN_CONFIG` JSON file
- Passed directly to `initialize(config)`

## Example Plugins

See the `example_tool/`, `example_skill/`, and `example_hooks/` directories for complete working examples.