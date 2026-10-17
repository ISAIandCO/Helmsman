import sys

mode = sys.argv.pop(1) if len(sys.argv) > 1 and sys.argv[1] in {"daemon", "ctl", "guard"} else "gui"
if mode == "daemon":
    from helmsman.daemon import main
elif mode == "ctl":
    from helmsman.rpc import main
elif mode == "guard":
    from helmsman.boot_guard import main
else:
    from helmsman.gui import main
main()
