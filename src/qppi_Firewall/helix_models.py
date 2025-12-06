from typing import Dict, Any
from .errors import PolicyViolation, ConsentRequired

def helix_data_integrity(policy: Dict[str, Any], profile: Dict[str, Any]) -> None:
    # Validate required fields and non-weapon constraints at definition level
    required = ["non_weapon", "digital_only", "contexts", "rate_limits", "consent"]
    for r in required:
        if r not in policy:
            raise PolicyViolation(f"Missing required policy field: {r}")
    if not policy["non_weapon"] or not policy["digital_only"]:
        raise PolicyViolation("Policy must enforce non-weapon and digital-only constraints")
    if "consent" not in profile or not profile["consent"].get("active"):
        raise ConsentRequired("Guardian consent seal is not active for this profile")

def helix_runtime_safety(policy: Dict[str, Any], runtime: Dict[str, Any], context: str) -> None:
    # Enforce context locks, cooldowns, session caps
    contexts = policy["contexts"]
    if context not in contexts:
        raise PolicyViolation(f"Context '{context}' not permitted")
    rate = policy["rate_limits"]
    session_count = runtime.get("session_count", 0)
    if session_count >= rate.get("max_sessions_per_day", 4):
        raise PolicyViolation("Max sessions per day reached")
    # Cooldown check
    import time
    last_end = runtime.get("last_end_ts")
    min_cooldown = rate.get("cooldown_seconds", 60)
    if last_end and (time.time() - last_end) < min_cooldown:
        raise PolicyViolation("Cooldown active; please wait")

def helix_audit_reflection(policy: Dict[str, Any], runtime: Dict[str, Any]) -> Dict[str, Any]:
    # Create a parity snapshot to compare DNA (policy) to RNA (runtime)
    snapshot = {
        "policy_hash_basis": sorted(policy.keys()),
        "runtime_basis": sorted(runtime.keys()),
        "parity_checks": {
            "non_weapon": policy.get("non_weapon", False),
            "digital_only": policy.get("digital_only", False),
        },
    }
    # Simple parity assertion: runtime must not define any out-of-policy capability keys
    out_of_scope = [k for k in runtime.keys() if k.startswith("cap_") and k not in policy.get("capabilities", [])]
    if out_of_scope:
        raise PolicyViolation(f"Runtime exceeded capabilities: {out_of_scope}")
    return snapshot

def helix_guardian_oversight(profile: Dict[str, Any], action: str) -> None:
    # Require consent active and check guardian pause/revoke flags
    consent = profile.get("consent", {})
    if not consent.get("active", False):
        raise ConsentRequired("Consent inactive; guardian must renew")
    if consent.get("paused", False) and action in ("start_session", "apply_policy"):
        raise PolicyViolation("Guardian pause is active")

def helix_joy_ceremony(policy: Dict[str, Any], context: str) -> None:
    # Ensure non-punitive, calm UX constraints exist for the context
    ux = policy.get("ux_constraints", {})
    required = ["no_jumpscare", "calm_transitions", "max_brightness", "max_volume"]
    if any(r not in ux for r in required):
        raise PolicyViolation("UX constraints incomplete for Joy helix")
    if context == "Play":
        # Play requires explicit “joy balance” to prevent overstimulation
        if not ux.get("joy_balance_timer_seconds", 300):
            raise PolicyViolation("Play context requires joy balance timer")
