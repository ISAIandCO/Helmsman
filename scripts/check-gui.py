import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from PySide6.QtWidgets import QApplication
from helmsman.common import defaults
from helmsman.gui import Window, theme

app = QApplication([])
theme(app)
w = Window()
w.timer.stop()
w.loaded(defaults())
w.resize(1280, 800)
w.show()
app.processEvents()
out = Path("test-results")
out.mkdir(exist_ok=True)
for i in range(w.tabs.count()):
    w.tabs.setCurrentIndex(i)
    app.processEvents()
    w.grab().save(str(out / f"desktop-{i}.png"))
for worker in list(w.workers):
    worker.wait(2000)
assert w.tabs.count() == 7
print("PASS seven native GUI pages rendered at 1280x800")
