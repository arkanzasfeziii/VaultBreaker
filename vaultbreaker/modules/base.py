"""Abstract base for VaultBreaker modules."""
from __future__ import annotations
from abc import ABC, abstractmethod
from vaultbreaker.models import EngagementContext
class BaseModule(ABC):
    name: str = "base"
    @abstractmethod
    def run(self, ctx: EngagementContext) -> None: ...
