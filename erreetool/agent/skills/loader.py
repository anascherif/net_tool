"""
Skill loader - reads YAML skill files, validates structure, caches parsed skills.
"""

import os
from pathlib import Path
from typing import Optional

import yaml

from erreetool.agent.skills.schema import (
    Skill,
    parse_skill,
)


class SkillLoader:
    """Loads and validates skill YAML files from a directory."""

    # Default skill directory (shipped with erreetool)
    DEFAULT_SKILL_DIR = Path(__file__).parent.parent.parent / "skills"

    def __init__(self, skill_dir: Path = None):
        self.skill_dir = skill_dir or self.DEFAULT_SKILL_DIR
        self._cache: dict[str, Skill] = {}
        self._plugin_cache: dict[str, Skill] = {}
        self._loaded = False

    def load_all(self, force: bool = False) -> list[Skill]:
        """Load all .yml skill files from the skill directory."""
        if self._loaded and not force:
            return list(self._cache.values()) + list(self._plugin_cache.values())

        self._cache.clear()
        self._loaded = False

        if not self.skill_dir.exists():
            return list(self._plugin_cache.values())

        for entry in sorted(self.skill_dir.iterdir()):
            if entry.suffix not in (".yml", ".yaml") or entry.name.startswith("_"):
                continue
            try:
                skill = self.load_file(entry)
                if skill:
                    self._cache[skill.name] = skill
            except Exception as e:
                print(f"Warning: Failed to load skill {entry.name}: {e}")
                continue

        self._loaded = True
        return list(self._cache.values()) + list(self._plugin_cache.values())

    def load_file(self, path: Path) -> Optional[Skill]:
        """Load and validate a single skill YAML file."""
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or not isinstance(data, dict):
            raise ValueError(f"Empty or invalid YAML: {path}")

        # Validate required fields
        if "name" not in data:
            raise ValueError(f"Skill missing required 'name' field: {path}")

        skill = parse_skill(data, source_file=str(path))

        # Validate tool requirements are known
        # (We don't check availability here - that's the executor's job)

        return skill

    def add_plugin_skill(self, skill: Skill) -> None:
        """Add a skill from a plugin."""
        self._plugin_cache[skill.name] = skill

    def remove_plugin_skill(self, name: str) -> bool:
        """Remove a plugin skill."""
        if name in self._plugin_cache:
            del self._plugin_cache[name]
            return True
        return False

    def get(self, name: str) -> Optional[Skill]:
        """Get a skill by name (loads if not yet loaded)."""
        if not self._loaded:
            self.load_all()
        # Check plugin cache first, then disk cache
        if name in self._plugin_cache:
            return self._plugin_cache[name]
        return self._cache.get(name)

    def list_names(self) -> list[str]:
        """List all loaded skill names."""
        if not self._loaded:
            self.load_all()
        return sorted(set(list(self._cache.keys()) + list(self._plugin_cache.keys())))

    def list_all(self) -> list[Skill]:
        """Get all loaded skills."""
        if not self._loaded:
            self.load_all()
        return list(self._cache.values()) + list(self._plugin_cache.values())

    def list_by_tag(self, tag: str) -> list[Skill]:
        """Get skills matching a given tag."""
        if not self._loaded:
            self.load_all()
        all_skills = list(self._cache.values()) + list(self._plugin_cache.values())
        return [s for s in all_skills if tag in s.tags]

    def reload(self) -> list[Skill]:
        """Force reload all skills from disk (preserves plugin skills)."""
        return self.load_all(force=True)


# Global loader instance
skill_loader = SkillLoader()
