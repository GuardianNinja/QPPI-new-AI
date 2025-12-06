import time
import hmac
import hashlib
from typing import Dict, Any, List, Optional

class InMemoryStore:
    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key
        self.policies: Dict[str, Dict[str, Any]] = {}
        self.profiles: Dict[str, Dict[str, Any]] = {}
        self.runtime: Dict[str, Dict[str, Any]] = {}
        self.audit_log: List[Dict[str, Any]] = {}
        self.emergency_stop: bool = False

    def _sign(self, payload: bytes) -> str:
        return hmac.new(self.secret_key, payload, hashlib.sha256).hexdigest()

    def log_event(self, actor: str, action: str, details: Dict[str, Any]) -> Dict[str, Any]:
        event = {
            "ts": time.time(),
            "actor": actor,
            "action": action,
            "details": details,
        }
        event["signature"] = self._sign(repr(event).encode("utf-8"))
        self.audit_log.setdefault("events", []).append(event)
        return event

    def set_policy(self, name: str, policy: Dict[str, Any]) -> None:
        self.policies[name] = policy
        self.log_event(actor="system", action="policy_set", details={"name": name})

    def get_policy(self, name: str) -> Optional[Dict[str, Any]]:
        return self.policies.get(name)

    def set_profile(self, name: str, profile: Dict[str, Any]) -> None:
        self.profiles[name] = profile
        self.log_event(actor="system", action="profile_set", details={"name": name})

    def get_profile(self, name: str) -> Optional[Dict[str, Any]]:
        return self.profiles.get(name)

    def set_runtime(self, name: str, runtime: Dict[str, Any]) -> None:
        self.runtime[name] = runtime
        self.log_event(actor="system", action="runtime_set", details={"name": name})

    def get_runtime(self, name: str) -> Optional[Dict[str, Any]]:
        return self.runtime.get(name)

    def engage_emergency_stop(self) -> None:
        self.emergency_stop = True
        self.log_event(actor="guardian", action="emergency_stop", details={})

    def release_emergency_stop(self) -> None:
        self.emergency_stop = False
        self.log_event(actor="guardian", action="emergency_release", details={})
