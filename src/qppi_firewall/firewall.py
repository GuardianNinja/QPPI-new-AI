import time
from typing import Dict, Any
from .storage import InMemoryStore
from .helix_models import (
    helix_data_integrity,
    helix_runtime_safety,
    helix_audit_reflection,
    helix_guardian_oversight,
    helix_joy_ceremony,
)
from .errors import PolicyViolation, EmergencyStopEngaged

class FiveHelixFirewall:
    def __init__(self, store: InMemoryStore):
        self.store = store

    def apply_policy(self, profile_name: str, policy_name: str) -> Dict[str, Any]:
        if self.store.emergency_stop:
            raise EmergencyStopEngaged("Emergency stop engaged")
        profile = self.store.get_profile(profile_name) or {}
        policy = self.store.get_policy(policy_name) or {}
        runtime = self.store.get_runtime(profile_name) or {"session_count": 0}

        # Helix 1: Data Integrity
        helix_data_integrity(policy, profile)
        # Helix 4: Guardian Oversight
        helix_guardian_oversight(profile, action="apply_policy")
        # Helix 5: Joy & Ceremony (baseline)
        helix_joy_ceremony(policy, context="Baseline")

        self.store.set_runtime(profile_name, runtime)
        self.store.log_event(actor="firewall", action="apply_policy", details={
            "profile": profile_name, "policy": policy_name
        })
        return {"ok": True, "msg": "Policy applied"}

    def start_session(self, profile_name: str, policy_name: str, context: str) -> Dict[str, Any]:
        if self.store.emergency_stop:
            raise EmergencyStopEngaged("Emergency stop engaged")
        profile = self.store.get_profile(profile_name) or {}
        policy = self.store.get_policy(policy_name) or {}
        runtime = self.store.get_runtime(profile_name) or {"session_count": 0}

        # Helix 4: Guardian Oversight
        helix_guardian_oversight(profile, action="start_session")
        # Helix 2: Runtime Safety
        helix_runtime_safety(policy, runtime, context)
        # Helix 5: Joy & Ceremony (context-aware)
        helix_joy_ceremony(policy, context=context)

        runtime["session_count"] = runtime.get("session_count", 0) + 1
        runtime["last_start_ts"] = time.time()
        self.store.set_runtime(profile_name, runtime)
        self.store.log_event(actor="firewall", action="start_session", details={
            "profile": profile_name, "policy": policy_name, "context": context
        })
        return {"ok": True, "msg": f"Session started ({context})"}

    def end_session(self, profile_name: str) -> Dict[str, Any]:
        runtime = self.store.get_runtime(profile_name) or {}
        runtime["last_end_ts"] = time.time()
        self.store.set_runtime(profile_name, runtime)
        snap = self.store.log_event(actor="firewall", action="end_session", details={
            "profile": profile_name
        })
        return {"ok": True, "msg": "Session ended", "event": snap}

    def parity_check(self, profile_name: str, policy_name: str) -> Dict[str, Any]:
        profile = self.store.get_profile(profile_name) or {}
        policy = self.store.get_policy(policy_name) or {}
        runtime = self.store.get_runtime(profile_name) or {}
        # Helix 3: Audit & Reflection
        snapshot = helix_audit_reflection(policy, runtime)
        self.store.log_event(actor="firewall", action="parity_check", details={
            "profile": profile_name, "policy": policy_name, "snapshot": snapshot
        })
        return {"ok": True, "snapshot": snapshot}

    def emergency_stop(self) -> Dict[str, Any]:
        self.store.engage_emergency_stop()
        return {"ok": True, "msg": "Emergency stop engaged"}

    def emergency_release(self) -> Dict[str, Any]:
        self.store.release_emergency_stop()
        return {"ok": True, "msg": "Emergency stop released"}
