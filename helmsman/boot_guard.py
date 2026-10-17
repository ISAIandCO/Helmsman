"""Arm before NetworkManager at boot when the last session requested protection."""
import json
from pathlib import Path
from .system import Runtime


def policy(directory):
    directory = Path(directory)
    try:
        state = json.loads((directory / "state.json").read_text())
        selected = next((p for p in state["profiles"] if p["id"] == state["selected"]), None)
        return bool(state["desired"] and state["settings"]["kill_switch"] and selected and selected["kind"] == "sing-box"), bool(state["settings"]["lan"])
    except (OSError, ValueError, KeyError, TypeError):
        # An independent last-known guard marker protects a damaged/missing
        # state file. With neither file this is a new, disconnected install.
        marker = directory / "guard.json"
        if not marker.exists():
            return False, False
        try:
            saved = json.loads(marker.read_text())
            return saved["armed"] is True, saved.get("lan") is True
        except (OSError, ValueError, KeyError, TypeError):
            return True, False


def main():
    armed, lan = policy("/opt/helmsman/state")
    runtime = Runtime("/opt/helmsman/current/engines", Path("/opt/helmsman/state/runtime"))
    if armed:
        runtime.install_guard(lan)
