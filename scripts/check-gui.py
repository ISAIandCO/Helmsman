"""Native GUI interactions and screenshots with synthetic, non-private fixtures."""
import copy
import sys
import time
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QCheckBox, QDialogButtonBox, QToolButton
from helmsman.common import defaults
from helmsman.gui import Window, theme
from helmsman.importers import parse
from helmsman.subscriptions import validate_subscription

app = QApplication([])
theme(app)
with patch.object(Window, 'refresh', lambda self: None):
    w = Window()
w.timer.stop()
saved_requests = []
w.request = lambda method, params=None, callback=None, quiet=False: saved_requests.append((method, params))
w.loaded(defaults())
assert not w.setting_widgets['auto_connect'].isChecked()
w.setting_widgets['auto_connect'].setChecked(True)
for key in ('dns_proxy', 'dns_direct'):
    selector = w.setting_widgets[key]
    for index in range(selector.picker.count() - 1):
        selector.choose(index)
        assert selector.value() == selector.picker.itemData(index)
    selector.set_value('tls://my-resolver.example:8853')
    assert selector.value() == 'tls://my-resolver.example:8853'
    assert selector.picker.currentData() == ''
w.save_settings()
assert saved_requests[-1][0] == 'settings_save'
assert saved_requests[-1][1]['settings']['dns_direct'] == 'tls://my-resolver.example:8853'
assert saved_requests[-1][1]['settings']['auto_connect'] is True
w.loaded(defaults())
w.resize(1280, 800)
w.show()
app.processEvents()
out = Path('test-results'); out.mkdir(exist_ok=True)
for index in (1, 2):
    w.nav_buttons[index].click()
    app.processEvents()
    assert w.tabs.currentIndex() == index
    w.grab().save(str(out / f'desktop-empty-{index}.png'))
fixture = defaults()
fixture['profiles'] = parse('vless://00000000-0000-0000-0000-000000000001@127.0.0.1:12345#Основной сервер\nhy2://test-password@127.0.0.1:12346#Резервный сервер')
fixture['profiles'][0]['outbound']['xray_mux'] = {'enabled': True, 'concurrency': 8}
fixture['selected'] = fixture['profiles'][0]['id']
fixture['subscriptions'] = [validate_subscription({'name': 'Моя подписка', 'url': 'https://example.test/sub', 'hwid_mode': 'remnawave'})]
fixture['subscriptions'][0]['last_update'] = time.time()
w.loaded(fixture)
status = {'state': 'running', 'message': 'Маршрутизация включена; доступность сервера проверяется отдельно.', 'guard': True, 'desired': True, 'selected': fixture['selected'], 'preset': fixture['preset'], 'profiles': [{'id': p['id'], 'protocol': p['outbound']['type']} for p in fixture['profiles']]}
w.show_status(status)
w.connect_button.click()
assert saved_requests[-1] == ('disconnect', {})
w.show_status({**status, 'state': 'disconnected', 'guard': False, 'desired': False})
w.connect_button.click()
assert saved_requests[-1] == ('connect', {'profile_id': fixture['selected']})
w.show_status(status)
w.profiles.setCurrentRow(1)
w.loaded(copy.deepcopy(fixture))
assert w.profiles.currentRow() == 1
assert w.profiles_empty.isHidden() and w.subscriptions_empty.isHidden()
for i in range(w.tabs.count()):
    w.nav_buttons[i].click()
    app.processEvents()
    assert w.nav_buttons[i].isChecked() and w.tabs.currentIndex() == i
    w.grab().save(str(out / f'desktop-{i}.png'))
for i in (0, 5):
    w.resize(960, 600)
    w.nav_buttons[i].click()
    app.processEvents()
    scroll = w.tabs.widget(i)
    assert scroll.widget().width() <= scroll.viewport().width(), (i, scroll.widget().width(), scroll.viewport().width())
    w.grab().save(str(out / f'desktop-small-{i}.png'))
for width, height in ((1280, 720), (1180, 688), (1060, 650), (960, 600)):
    w.resize(width, height); w.nav_buttons[0].click()
    for _ in range(3): app.processEvents()
    scroll = w.tabs.widget(0)
    assert scroll.verticalScrollBar().maximum() == 0, (width, height, scroll.verticalScrollBar().maximum())
    w.grab().save(str(out / f'desktop-fit-{width}x{height}.png'))
print('PASS dashboard fits KDE client areas down to 960x600 without vertical scrolling')
w.resize(1280, 800)

def modal(invoke, action):
    errors = []
    def execute():
        dialog = app.activeModalWidget()
        try:
            assert dialog is not None
            action(dialog)
        except BaseException as e:
            errors.append(e)
            if dialog: dialog.reject()
    QTimer.singleShot(100, execute)
    invoke()
    if errors: raise errors[0]

def warp_dialog(dialog):
    save = dialog.findChild(QDialogButtonBox).button(QDialogButtonBox.Save)
    assert not save.isEnabled()
    dialog.findChild(QCheckBox).setChecked(True)
    assert save.isEnabled()
    dialog.grab().save(str(out / 'desktop-warp.png'))
    dialog.reject()  # No external registration in CI.
modal(w.generate_warp, warp_dialog)
print('PASS WARP native dialog and explicit consent')
saved_requests.clear()
def subscription_dialog(dialog):
    fields = dialog.fields
    fields['url'][1].setText('https://example.test/sub')
    mode = fields['mode'][1]
    assert not fields['hwid_params'][1].isVisible()
    mode.setCurrentIndex(mode.findData('remnawave'))
    fields['hwid_params'][1].setPlainText('hwid=0123456789abcdef,os=Android,osVersion=16,model=Test Device')
    fields['user_agent'][1].setText('v2rayNG/1.10.5')
    assert fields['hwid_params'][1].isEnabled() and fields['hwid_params'][1].isVisible()
    assert not fields['hwid_name'][1].isEnabled()
    dialog.grab().save(str(out / 'desktop-subscription.png'))
    for toggle in dialog.findChildren(QToolButton):
        if toggle.isCheckable(): toggle.setChecked(True)
    app.processEvents()
    assert fields['user_agent'][1].isVisible()
    dialog.grab().save(str(out / 'desktop-subscription-advanced.png'))
    dialog.accept()
modal(w.edit_subscription, subscription_dialog)
assert saved_requests[0][0] == 'subscription_save'
assert saved_requests[0][1]['hwid_params'].startswith('hwid=0123456789abcdef,')
assert saved_requests[0][1]['user_agent'] == 'v2rayNG/1.10.5'
assert w.tabs.count() == 7
w.nav_buttons[0].click(); app.processEvents()
print('PASS seven GUI pages at 1280x800 and 960x600, navigation, connection actions, DNS and subscription settings')
w.close()
