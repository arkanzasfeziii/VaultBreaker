"""Exceptions for VaultBreaker."""
class VaultBreakerError(Exception): pass
class ModuleError(VaultBreakerError): pass
class DependencyError(VaultBreakerError):
    def __init__(self, p: str) -> None: super().__init__(f"Missing: {p}")
