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
saved_requests = []
original_request = w.request
w.request = lambda method, params=None, callback=None, quiet=False: saved_requests.append((method, params))
def subscription_dialog():
    dialog = app.activeModalWidget()
    fields = dialog.fields
    fields['url'][1].setText('https://example.test/sub')
    mode = fields['mode'][1]
    mode.setCurrentIndex(mode.findData('remnawave'))
    fields['hwid_params'][1].setPlainText('hwid=0123456789abcdef,os=Android,osVersion=16,model=Test Device')
    fields['user_agent'][1].setText('v2rayNG/1.10.5')
    assert fields['hwid_params'][1].isEnabled()
    assert not fields['hwid_name'][1].isEnabled()
    dialog.grab().save(str(out / 'desktop-subscription.png'))
    dialog.accept()
QTimer.singleShot(100, subscription_dialog)
w.edit_subscription()
assert saved_requests[0][0] == 'subscription_save'
assert saved_requests[0][1]['hwid_params'].startswith('hwid=0123456789abcdef,')
assert saved_requests[0][1]['user_agent'] == 'v2rayNG/1.10.5'
w.request = original_request
print('PASS native subscription editor saves NekoBox HWID parameters and User-Agent')
for worker in list(w.workers):
    worker.wait(2000)
assert w.tabs.count() == 7
print("PASS seven native GUI pages rendered at 1280x800")
