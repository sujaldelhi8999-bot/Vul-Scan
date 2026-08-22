"""
Skill Loader - Loads and parses skill YAML files.
"""

import os
import yaml
from pathlib import Path
from typing import Any, Optional
from functools import lru_cache

from pydantic import BaseModel, Field


class SkillMetadata(BaseModel):
    """Skill front-matter metadata."""
    name: str
    description: str
    category: str = "vulnerabilities"
    version: str = "1.0"
    tags: list[str] = Field(default_factory=list)
    applies_to: list[str] = Field(default_factory=list)  # technologies, frameworks
    severity: str = "MEDIUM"  # default severity for findings from this skill
    confidence_threshold: str = "MEDIUM"


class SkillPayload(BaseModel):
    """Structured skill content."""
    attack_surface: list[str] = Field(default_factory=list)
    detection_channels: list[str] = Field(default_factory=list)
    payload_primitives: dict[str, list[str]] = Field(default_factory=dict)
    false_positive_validation: list[str] = Field(default_factory=list)
    chaining_guidance: list[str] = Field(default_factory=list)
    remediation_patterns: list[str] = Field(default_factory=list)
    code_locations: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class Skill(BaseModel):
    """Complete skill with metadata and payload."""
    metadata: SkillMetadata
    payload: SkillPayload
    raw_content: str = ""
    file_path: str = ""


class SkillLoader:
    """Loads skills from YAML files in skill directories."""
    
    def __init__(self, skill_dirs: Optional[list[str]] = None):
        self.skill_dirs = skill_dirs or [self._default_skill_dir()]
        self._skills_cache: dict[str, Skill] = {}
        self._loaded = False
    
    @staticmethod
    def _default_skill_dir() -> str:
        return str(Path(__file__).parent / "vulnerabilities")
    
    def load_all(self) -> dict[str, Skill]:
        """Load all skills from all skill directories."""
        if self._loaded:
            return self._skills_cache
        
        for skill_dir in self.skill_dirs:
            self._load_from_dir(skill_dir)
        
        self._loaded = True
        return self._skills_cache
    
    def _load_from_dir(self, skill_dir: str) -> None:
        path = Path(skill_dir)
        if not path.exists():
            return
        
        for yaml_file in path.glob("*.yaml"):
            try:
                skill = self._parse_skill_file(yaml_file)
                if skill:
                    self._skills_cache[skill.metadata.name] = skill
            except Exception as e:
                print(f"Warning: Failed to load skill {yaml_file}: {e}")
    
    def _parse_skill_file(self, file_path: Path) -> Optional[Skill]:
        content = file_path.read_text(encoding="utf-8")
        
        # Parse YAML front matter
        if content.startswith("---"):
            parts = content.split("---", 2)
            if len(parts) >= 3:
                front_matter = yaml.safe_load(parts[1])
                body = parts[2].strip()
            else:
                front_matter = {}
                body = content
        else:
            front_matter = {}
            body = content
        
        # Parse body as additional YAML if it looks structured, otherwise treat as markdown
        try:
            payload_data = yaml.safe_load(body)
            if not isinstance(payload_data, dict):
                payload_data = {}
        except yaml.YAMLError:
            payload_data = {}
        
        metadata = SkillMetadata(
            name=front_matter.get("name", file_path.stem),
            description=front_matter.get("description", ""),
            category=front_matter.get("category", "vulnerabilities"),
            version=front_matter.get("version", "1.0"),
            tags=front_matter.get("tags", []),
            applies_to=front_matter.get("applies_to", []),
            severity=front_matter.get("severity", "MEDIUM"),
            confidence_threshold=front_matter.get("confidence_threshold", "MEDIUM"),
        )
        
        payload = SkillPayload(
            attack_surface=payload_data.get("attack_surface", []),
            detection_channels=payload_data.get("detection_channels", []),
            payload_primitives=payload_data.get("payload_primitives", {}),
            false_positive_validation=payload_data.get("false_positive_validation", []),
            chaining_guidance=payload_data.get("chaining_guidance", []),
            remediation_patterns=payload_data.get("remediation_patterns", []),
            code_locations=payload_data.get("code_locations", []),
            references=payload_data.get("references", []),
        )
        
        return Skill(
            metadata=metadata,
            payload=payload,
            raw_content=content,
            file_path=str(file_path),
        )
    
    def get_skill(self, name: str) -> Optional[Skill]:
        """Get a skill by name, loading all if necessary."""
        if not self._loaded:
            self.load_all()
        return self._skills_cache.get(name)
    
    def list_skills(self, category: Optional[str] = None) -> list[Skill]:
        """List all loaded skills, optionally filtered by category."""
        if not self._loaded:
            self.load_all()
        skills = list(self._skills_cache.values())
        if category:
            skills = [s for s in skills if s.metadata.category == category]
        return skills
    
    def get_skills_for_context(
        self, 
        target_tech: Optional[list[str]] = None,
        vulnerability_types: Optional[list[str]] = None,
        max_skills: int = 5
    ) -> list[Skill]:
        """Select relevant skills for a given context."""
        if not self._loaded:
            self.load_all()
        
        skills = list(self._skills_cache.values())
        
        # Score skills by relevance
        scored = []
        for skill in skills:
            score = 0
            if target_tech:
                for tech in target_tech:
                    if tech.lower() in [t.lower() for t in skill.metadata.applies_to]:
                        score += 2
                    if any(tech.lower() in tag.lower() for tag in skill.metadata.tags):
                        score += 1
            
            if vulnerability_types:
                for vuln in vulnerability_types:
                    if vuln.lower() in skill.metadata.name.lower():
                        score += 3
                    if vuln.lower() in [t.lower() for t in skill.metadata.tags]:
                        score += 1
            
            scored.append((score, skill))
        
        scored.sort(key=lambda x: x[0], reverse=True)
        return [s for _, s in scored[:max_skills]]
    
    def format_skill_for_prompt(self, skill: Skill, include_payload: bool = True) -> str:
        """Format a skill for injection into an LLM prompt."""
        lines = [
            f"## Skill: {skill.metadata.name}",
            f"**Description**: {skill.metadata.description}",
            f"**Category**: {skill.metadata.category}",
            f"**Severity**: {skill.metadata.severity}",
        ]
        
        if skill.metadata.applies_to:
            lines.append(f"**Applies to**: {', '.join(skill.metadata.applies_to)}")
        
        if include_payload:
            payload = skill.payload
            if payload.attack_surface:
                lines.append("\n### Attack Surface")
                lines.extend(f"- {item}" for item in payload.attack_surface)
            
            if payload.detection_channels:
                lines.append("\n### Detection Channels")
                lines.extend(f"- {item}" for item in payload.detection_channels)
            
            if payload.payload_primitives:
                lines.append("\n### Payload Primitives")
                for category, primitives in payload.payload_primitives.items():
                    lines.append(f"\n**{category}**:")
                    lines.extend(f"- `{p}`" for p in primitives[:10])  # limit for token budget
            
            if payload.false_positive_validation:
                lines.append("\n### False Positive Validation")
                lines.extend(f"- {item}" for item in payload.false_positive_validation)
            
            if payload.chaining_guidance:
                lines.append("\n### Chaining Guidance")
                lines.extend(f"- {item}" for item in payload.chaining_guidance)
            
            if payload.remediation_patterns:
                lines.append("\n### Remediation Patterns")
                lines.extend(f"- {item}" for item in payload.remediation_patterns)
            
            if payload.code_locations:
                lines.append("\n### Common Code Locations")
                lines.extend(f"- {item}" for item in payload.code_locations)
            
            if payload.references:
                lines.append("\n### References")
                lines.extend(f"- {item}" for item in payload.references[:5])
        
        return "\n".join(lines)


# Global loader instance
_loader: Optional[SkillLoader] = None


def get_loader() -> SkillLoader:
    global _loader
    if _loader is None:
        _loader = SkillLoader()
    return _loader


def load_skill(name: str) -> Optional[Skill]:
    """Load a single skill by name."""
    return get_loader().get_skill(name)


def list_skills(category: Optional[str] = None) -> list[Skill]:
    """List all skills, optionally filtered by category."""
    return get_loader().list_skills(category)


def get_skills_for_prompt(
    target_tech: Optional[list[str]] = None,
    vulnerability_types: Optional[list[str]] = None,
    max_skills: int = 5
) -> str:
    """Get formatted skills for prompt injection."""
    skills = get_loader().get_skills_for_context(
        target_tech=target_tech,
        vulnerability_types=vulnerability_types,
        max_skills=max_skills
    )
    return "\n\n".join(get_loader().format_skill_for_prompt(s) for s in skills)