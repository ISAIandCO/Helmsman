import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QCheckBox, QDialogButtonBox
from helmsman.common import defaults
from helmsman.gui import Window, theme

app = QApplication([])
theme(app)
w = Window()
w.timer.stop()
w.loaded(defaults())
for key in ("dns_proxy", "dns_direct"):
    selector = w.setting_widgets[key]
    for index in range(selector.picker.count() - 1):
        selector.choose(index)
        assert selector.value() == selector.picker.itemData(index)
    selector.set_value("tls://my-resolver.example:8853")
    assert selector.value() == "tls://my-resolver.example:8853"
    assert selector.picker.currentData() == ""
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
def warp_dialog():
    dialog = app.activeModalWidget()
    assert dialog is not None
    save = dialog.findChild(QDialogButtonBox).button(QDialogButtonBox.Save)
    assert not save.isEnabled()
    dialog.findChild(QCheckBox).setChecked(True)
    assert save.isEnabled()
    dialog.grab().save(str(out / "desktop-warp.png"))
    dialog.reject()  # No external registration in CI.
QTimer.singleShot(100, warp_dialog)
w.generate_warp()
print("PASS WARP native dialog and explicit consent")
for worker in list(w.workers):
    worker.wait(2000)
assert w.tabs.count() == 7
print("PASS seven native GUI pages rendered at 1280x800")
