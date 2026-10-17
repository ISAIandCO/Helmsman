"""Arm before NetworkManager at boot when the last session requested protection."""
from pathlib import Path
from .common import Store
from .system import Runtime


def main():
    store = Store("/var/lib/helmsman")
    state = store.data
    selected = next((p for p in state["profiles"] if p["id"] == state["selected"]), None)
    runtime = Runtime("/var/lib/helmsman-app/current/engines", Path("/var/lib/helmsman/runtime"))
    if state["desired"] and state["settings"]["kill_switch"] and selected and selected["kind"] == "sing-box":
        runtime.install_guard(state["settings"]["lan"])
