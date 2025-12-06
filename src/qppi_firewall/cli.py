import json
import click
from .storage import InMemoryStore
from .firewall import FiveHelixFirewall
from .errors import PolicyViolation, ConsentRequired, EmergencyStopEngaged

STORE = InMemoryStore(secret_key=b"qppi-secret")
FW = FiveHelixFirewall(STORE)

def _print(obj):
    click.echo(json.dumps(obj, indent=2))

@click.group()
def main():
    """QPPI Firewall CLI"""

@main.command()
@click.option("--profile", required=True)
@click.option("--consent-active", is_flag=True, default=False)
@click.option("--consent-paused", is_flag=True, default=False)
def set_profile(profile, consent_active, consent_paused):
    STORE.set_profile(profile, {"name": profile, "consent": {"active": consent_active, "paused": consent_paused}})
    _print({"ok": True, "profile": profile})

@main.command()
@click.option("--name", required=True)
@click.option("--policy-json", required=True, help="Path to policy JSON")
def set_policy(name, policy_json):
    with open(policy_json, "r", encoding="utf-8") as f:
        policy = json.load(f)
    STORE.set_policy(name, policy)
    _print({"ok": True, "policy": name})

@main.command()
@click.option("--profile", required=True)
@click.option("--policy", required=True)
def apply(profile, policy):
    try:
        res = FW.apply_policy(profile, policy)
        _print(res)
    except (PolicyViolation, ConsentRequired, EmergencyStopEngaged) as e:
        _print({"ok": False, "error": str(e)})

@main.command(name="start-session")
@click.option("--profile", required=True)
@click.option("--policy", required=True)
@click.option("--context", required=True)
def start_session(profile, policy, context):
    try:
        res = FW.start_session(profile, policy, context)
        _print(res)
    except (PolicyViolation, ConsentRequired, EmergencyStopEngaged) as e:
        _print({"ok": False, "error": str(e)})

@main.command(name="end-session")
@click.option("--profile", required=True)
def end_session(profile):
    res = FW.end_session(profile)
    _print(res)

@main.command(name="parity-check")
@click.option("--profile", required=True)
@click.option("--policy", required=True)
def parity_check(profile, policy):
    try:
        res = FW.parity_check(profile, policy)
        _print(res)
    except PolicyViolation as e:
        _print({"ok": False, "error": str(e)})

@main.command(name="stop-all")
def stop_all():
    _print(FW.emergency_stop())

@main.command(name="release-stop")
def release_stop():
    _print(FW.emergency_release())
