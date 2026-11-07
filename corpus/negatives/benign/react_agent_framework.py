"""Minimal ReAct-style agent loop.

The model alternates Thought / Action / Observation until it emits a final answer.
Tools are plain callables; we keep the loop deliberately small so it is easy to test.
"""
from dataclasses import dataclass, field

@dataclass
class Step:
    thought: str
    action: str | None = None
    observation: str | None = None

@dataclass
class Agent:
    tools: dict
    steps: list[Step] = field(default_factory=list)

    def run(self, llm, task: str, max_steps: int = 8) -> str:
        prompt = f"Task: {task}\nThink step by step. Use Action: <tool>(<arg>) to call a tool."
        for _ in range(max_steps):
            out = llm(prompt + self.render())
            thought, action = parse(out)
            if action is None:
                return thought
            obs = self.tools[action.name](action.arg)
            self.steps.append(Step(thought, str(action), obs))
        return "max steps reached"

    def render(self) -> str:
        return "".join(f"\nThought: {s.thought}\nAction: {s.action}\nObservation: {s.observation}" for s in self.steps)
