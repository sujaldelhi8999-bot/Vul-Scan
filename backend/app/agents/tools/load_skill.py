"""
Load Skill Tool - Runtime skill loading for agents.

Allows agents to dynamically load skill knowledge packages during execution.
Max 5 skills per agent as per Strix design.
"""

from typing import Any

from app.skills import load_skill, list_skills, get_skills_for_prompt
from app.agents import Agent


class LoadSkillTool:
    """Tool for loading skill knowledge at runtime."""
    
    def __init__(self, agent: Agent):
        self.agent = agent
        self.loaded_skills: list[str] = []
        self.max_skills = 5
    
    async def load_skill(self, skill_name: str) -> dict[str, Any]:
        """
        Load a skill by name.
        
        Args:
            skill_name: Name of the skill to load (e.g., 'sql_injection', 'xss')
            
        Returns:
            Skill content formatted for agent consumption
        """
        if len(self.loaded_skills) >= self.max_skills:
            return {
                "error": f"Maximum skills ({self.max_skills}) already loaded",
                "loaded_skills": self.loaded_skills,
            }
        
        skill = load_skill(skill_name)
        if not skill:
            available = [s.metadata.name for s in list_skills()]
            return {
                "error": f"Skill '{skill_name}' not found",
                "available_skills": available[:20],
            }
        
        if skill_name in self.loaded_skills:
            return {
                "message": f"Skill '{skill_name}' already loaded",
                "skill": skill.metadata.name,
            }
        
        self.loaded_skills.append(skill_name)
        
        from app.skills.loader import get_loader
        loader = get_loader()
        formatted = loader.format_skill_for_prompt(skill)
        
        await self.agent.log_action(
            "skill_loaded",
            f"Loaded skill: {skill_name}"
        )
        
        return {
            "skill": skill.metadata.name,
            "description": skill.metadata.description,
            "category": skill.metadata.category,
            "severity": skill.metadata.severity,
            "content": formatted,
            "loaded_count": len(self.loaded_skills),
        }
    
    async def list_skills(self, category: str | None = None) -> dict[str, Any]:
        """List available skills, optionally filtered by category."""
        skills = list_skills(category)
        return {
            "skills": [
                {
                    "name": s.metadata.name,
                    "description": s.metadata.description,
                    "category": s.metadata.category,
                    "tags": s.metadata.tags,
                    "applies_to": s.metadata.applies_to,
                    "severity": s.metadata.severity,
                }
                for s in skills
            ],
            "total": len(skills),
        }
    
    async def get_skills_for_context(
        self,
        target_tech: list[str] | None = None,
        vulnerability_types: list[str] | None = None,
    ) -> dict[str, Any]:
        """Get relevant skills for the current context."""
        skills_text = get_skills_for_prompt(
            target_tech=target_tech,
            vulnerability_types=vulnerability_types,
            max_skills=self.max_skills - len(self.loaded_skills),
        )
        return {
            "skills_context": skills_text,
            "currently_loaded": self.loaded_skills,
        }
    
    async def clear_skills(self) -> dict[str, Any]:
        """Clear all loaded skills."""
        count = len(self.loaded_skills)
        self.loaded_skills.clear()
        return {"message": f"Cleared {count} loaded skills"}


async def create_load_skill_tool(agent: Agent) -> LoadSkillTool:
    """Factory function to create a LoadSkillTool for an agent."""
    return LoadSkillTool(agent)