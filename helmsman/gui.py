"""Native Qt desktop client. All network operations belong to the service."""
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from PySide6.QtCore import QThread, QTimer, Signal, Qt, QSize
from PySide6.QtWidgets import (QApplication, QButtonGroup, QCheckBox, QFrame, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSpinBox, QStackedWidget, QScroller, QToolButton, QVBoxLayout, QWidget)

from .i18n import tr, set_language, language, translate_message
from .regions import COUNTRIES, PRESETS, BUILTIN_LISTS, available_presets, preset_description
from .common import MAX_BYTES, UserError, VERSION
from .dns import DNS_PRESETS, resolver_url
from .rpc import call
from .subscriptions import SUBSCRIPTION_AGENT, subscription_agent
from .warp import TERMS
from .xray import is_xhttp
from .ui import COLORS, ListDelegate, Switch, card, disclosure, icon, label, theme


class Request(QThread):
    done = Signal(object)
    failed = Signal(str)
    def __init__(self, method, params):
        super().__init__()
        self.method, self.params = method, params

    def run(self):
        try:
            self.done.emit(call(self.method, self.params))
        except UserError as e:
            self.failed.emit(str(e))


def button(text, callback, layout, variant='', symbol=''):
    b = QPushButton(text)
    if variant:
        b.setProperty('variant', variant)
    if symbol:
        b.setIcon(icon(symbol, '#271b41' if variant in {'primary', 'connect'} else '#d1c5e4'))
        b.setIconSize(QSize(20, 20))
    b.clicked.connect(callback)
    layout.addWidget(b)
    return b


def combo(items):
    c = QComboBox()
    for key, text in items.items():
        c.addItem(tr(text), key)
    return c


class Form(QDialog):
    def __init__(self, title, fields, parent, advanced=()):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(720, 700)
        self.fields = fields
        self.rows = {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(18)
        layout.addWidget(label(title, 'cardTitle'))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        QScroller.grabGesture(scroll.viewport(), QScroller.TouchGesture)
        page = QWidget(); page.setObjectName('page')
        body = QVBoxLayout(page); body.setContentsMargins(0, 0, 8, 0); body.setSpacing(18)
        form = QVBoxLayout(); form.setSpacing(16)
        body.addLayout(form)
        extra = None
        if advanced:
            pane = disclosure(tr('Дополнительные настройки'), body)
            extra = QVBoxLayout(); extra.setSpacing(16); pane.addLayout(extra)
        for key, (name, widget) in fields.items():
            widget.setAccessibleName(name)
            target = extra if key in advanced else form
            row = QWidget(); row.setObjectName('transparent')
            stack = QVBoxLayout(row); stack.setContentsMargins(0, 0, 0, 0); stack.setSpacing(7)
            if name:
                stack.addWidget(label(name, 'caption'))
            stack.addWidget(widget)
            target.addWidget(row)
            self.rows[key] = row
        body.addStretch()
        scroll.setWidget(page)
        layout.addWidget(scroll)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Save).setText(tr('Сохранить'))
        buttons.button(QDialogButtonBox.Save).setProperty('variant', 'primary')
        buttons.button(QDialogButtonBox.Save).style().unpolish(buttons.button(QDialogButtonBox.Save))
        buttons.button(QDialogButtonBox.Save).style().polish(buttons.button(QDialogButtonBox.Save))
        buttons.button(QDialogButtonBox.Cancel).setText(tr('Отмена'))
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def show_field(self, key, visible):
        self.rows[key].setVisible(visible)


def line(text="", secret=False):
    w = QLineEdit(str(text))
    if secret:
        w.setEchoMode(QLineEdit.Password)
    return w


def area(text=""):
    w = QPlainTextEdit(str(text))
    w.setMinimumHeight(100)
    return w


def integer(value, minimum, maximum):
    w = QSpinBox()
    w.setRange(minimum, maximum)
    w.setValue(int(value))
    return w


class DNSSelector(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(3)
        self.picker = combo({url: name for name, url in DNS_PRESETS})
        self.picker.setMinimumContentsLength(10)
        self.picker.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.picker.addItem(tr("Свой сервер…"), "")
        self.address = line()
        self.address.setPlaceholderText(tr("https://сервер/dns-query или tls://сервер:853"))
        self.address.setAccessibleName(tr("Адрес DNS DoH или DoT"))
        self.picker.setAccessibleName(tr("Готовый DNS или свой сервер"))
        layout.addWidget(self.picker)
        layout.addWidget(self.address)
        self.picker.activated.connect(self.choose)
        self.address.textEdited.connect(self.edited)

    def choose(self, index):
        self.address.setText(self.picker.itemData(index))
        if not self.address.text():
            self.address.setFocus()

    def edited(self, value):
        index = self.picker.findData(value)
        self.picker.setCurrentIndex(index if index >= 0 else self.picker.count() - 1)

    def value(self):
        return self.address.text()

    def set_value(self, value):
        try:
            value = resolver_url(value)
        except UserError:
            pass
        self.address.setText(value)
        self.edited(value)


class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Helmsman")
        self.setMinimumSize(960, 600)
        available = QApplication.primaryScreen().availableGeometry()
        self.resize(min(1180, available.width() - 32), min(720, available.height() - 64))
        self.setWindowIcon(icon('compass', COLORS['primary'], 64))
        self.config = None
        self.workers = set()
        self.busy = False
        self.connection_desired = False
        self.build_ui()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll)
        self.timer.start(3000)
        self.refresh()

    def build_ui(self):
        old = self.takeCentralWidget()
        if old:
            old.deleteLater()
            self.nav_group.deleteLater()
        shell = QWidget(); shell.setObjectName('shell')
        root = QHBoxLayout(shell); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)
        sidebar = QWidget(); sidebar.setObjectName('sidebar'); sidebar.setFixedWidth(204)
        side = QVBoxLayout(sidebar); side.setContentsMargins(14, 26, 14, 20); side.setSpacing(7)
        brand = QHBoxLayout(); brand.setContentsMargins(7, 0, 0, 24)
        mark = QLabel(); mark.setPixmap(icon('compass', COLORS['primary'], 32).pixmap(32, 32))
        brand.addWidget(mark); brand.addWidget(label('Helmsman', 'brand')); brand.addStretch()
        side.addLayout(brand)
        self.navigation = QVBoxLayout(); self.navigation.setSpacing(8); side.addLayout(self.navigation)
        self.nav_buttons = []
        self.nav_group = QButtonGroup(self)
        side.addStretch()
        side.addWidget(label('STEAM DECK', 'eyebrow'))
        side.addWidget(label('Desktop + Decky', 'caption'))
        side.addWidget(label(VERSION, 'caption'))
        root.addWidget(sidebar)
        workspace = QVBoxLayout(); workspace.setContentsMargins(30, 24, 30, 8); workspace.setSpacing(18)
        heading = QHBoxLayout()
        titles = QVBoxLayout(); titles.setSpacing(6)
        self.page_title = label('', 'pageTitle')
        self.page_caption = label('', 'caption')
        titles.addWidget(self.page_title); titles.addWidget(self.page_caption)
        heading.addLayout(titles, 1)
        self.service_badge = label(tr('Ожидание сервиса'), 'badge')
        self.service_badge.setAlignment(Qt.AlignCenter)
        heading.addWidget(self.service_badge, 0, Qt.AlignTop)
        workspace.addLayout(heading)
        self.tabs = QStackedWidget()
        self.tabs.currentChanged.connect(self.page_changed)
        self.page_titles = []
        workspace.addWidget(self.tabs, 1)
        root.addLayout(workspace, 1)
        self.setCentralWidget(shell)
        self.build_connection()
        self.build_profiles()
        self.build_subscriptions()
        self.build_rules()
        self.build_lists()
        self.build_settings()
        self.build_diagnostics()

    def page(self, name):
        descriptions = {
            tr('Подключение'): (tr('Ваше соединение'), tr('Выберите подключение и маршрут для интернета.')),
            tr('Профили'): (tr('Подключения'), tr('Ваши серверы и виртуальные сети.')),
            tr('Подписки'): (tr('Подписки'), tr('Управляйте списками серверов и обновлениями.')),
            tr('Правила'): (tr('Маршрутизация'), tr('Решайте, какой трафик идёт через подключение.')),
            tr('Списки'): (tr('Списки адресов'), tr('Домены и IP для ваших правил.')),
            tr('Настройки'): (tr('Настройки'), tr('Защита соединения, DNS и поведение сервиса.')),
            tr('Диагностика'): (tr('Диагностика'), tr('Состояние сервиса и последние события.')),
        }
        symbols = ['home', 'profiles', 'subscriptions', 'rules', 'lists', 'settings', 'diagnostics']
        index = len(self.nav_buttons)
        nav = QPushButton(name); nav.setObjectName('nav'); nav.setCheckable(True)
        nav.setFixedHeight(50); nav.setIcon(icon(symbols[index])); nav.setIconSize(QSize(22,22))
        nav.setAccessibleName(name); nav.setShortcut('Alt+' + str(index+1))
        nav.clicked.connect(lambda checked=False, i=index: self.tabs.setCurrentIndex(i))
        self.nav_group.addButton(nav); self.nav_buttons.append(nav); self.navigation.addWidget(nav)
        self.page_titles.append(descriptions[name])
        content = QWidget(); content.setObjectName('page')
        layout = QVBoxLayout(content); layout.setContentsMargins(0, 0, 8, 8); layout.setSpacing(16)
        scroll = QScrollArea(); scroll.setFrameShape(QFrame.NoFrame); scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        QScroller.grabGesture(scroll.viewport(), QScroller.TouchGesture)
        scroll.setWidget(content)
        self.tabs.addWidget(scroll)
        return layout

    def page_changed(self, index):
        if 0 <= index < len(self.nav_buttons):
            self.nav_buttons[index].setChecked(True)
            title, caption = self.page_titles[index]
            self.page_title.setText(title); self.page_caption.setText(caption)

    def collection(self, title):
        view = QListWidget(); view.setAccessibleName(title)
        view.setItemDelegate(ListDelegate(view)); view.setSpacing(2)
        view.setMinimumHeight(160)
        return view

    def empty(self, title, message):
        frame, body = card()
        body.addStretch()
        body.addWidget(label(title, 'cardTitle'))
        body.addWidget(label(message, 'body'))
        body.addStretch()
        return frame

    def request(self, method, params=None, callback=None, quiet=False):
        worker = Request(method, params or {})
        self.workers.add(worker)
        if not quiet:
            self.busy = True
            self.statusBar().showMessage(tr("Выполняется…"))
        def success(result):
            if not quiet:
                self.busy = False
                self.statusBar().showMessage(tr("Готово"), 3000)
            if callback:
                callback(result)
        def failure(message):
            message = translate_message(message, language())
            if not quiet:
                self.busy = False
                QMessageBox.warning(self, "Helmsman", translate_message(message, language()))
            self.statusBar().showMessage(translate_message(message, language()), 10000)
            if method in {'status', 'configuration'}:
                self.service_badge.setText(tr('Сервис недоступен'))
                self.state_title.setText(tr('Нет связи с сервисом'))
                self.state_label.setText(message)
                self.guard_badge.setText(tr('Состояние неизвестно'))
                self.guard_badge.setProperty('active', False)
                self.guard_badge.style().unpolish(self.guard_badge); self.guard_badge.style().polish(self.guard_badge)
                self.connect_button.setEnabled(False)
        worker.done.connect(success)
        worker.failed.connect(failure)
        worker.finished.connect(lambda: self.workers.discard(worker))
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def mutate(self, method, params=None):
        if not self.busy:
            self.request(method, params, lambda _: self.refresh())

    def refresh(self):
        self.request("configuration", callback=self.loaded, quiet=True)
        self.poll()

    def poll(self):
        if not self.busy and not self.workers:
            self.request("status", callback=self.show_status, quiet=True)

    def build_connection(self):
        l = self.page(tr('Подключение'))
        l.setSpacing(12)
        row = QHBoxLayout(); row.setSpacing(18)
        hero, body = card(role='heroCard')
        body.setContentsMargins(20, 18, 20, 18); body.setSpacing(10)
        top = QHBoxLayout()
        mark = QLabel(); mark.setPixmap(icon('power', COLORS['primary'], 28).pixmap(28,28)); mark.setFixedSize(28,28)
        top.addWidget(mark)
        top.addWidget(label(tr('ПОДКЛЮЧЕНИЕ'), 'eyebrow')); top.addStretch()
        self.guard_badge = label(tr('Защита выключена'), 'badge'); top.addWidget(self.guard_badge)
        body.addLayout(top)
        self.state_title = label(tr('Добро пожаловать'), 'stateTitle'); body.addWidget(self.state_title)
        self.state_label = label(tr('Ожидание сервиса…'), 'body'); self.state_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        body.addWidget(self.state_label)
        body.addSpacing(12)
        body.addWidget(label(tr('Выбранное подключение'), 'caption'))
        self.profile_picker = QComboBox(); self.profile_picker.setAccessibleName(tr('Выбранное подключение'))
        self.profile_picker.setMinimumContentsLength(16); self.profile_picker.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.profile_picker.activated.connect(lambda _: self.mutate('select', {'profile_id': self.profile_picker.currentData()}))
        body.addWidget(self.profile_picker)
        self.connect_button = button(tr('Подключить'), self.toggle_connection, body, 'connect', 'power')
        self.connect_button.setEnabled(False)
        button(tr('Проверить подключение'), lambda: self.request('probe', callback=lambda r: QMessageBox.information(self, tr('Проверка'), r['message'])), body, 'text', 'diagnostics')
        body.addStretch()
        row.addWidget(hero, 3)
        right = QVBoxLayout(); right.setSpacing(12)
        _, route = card(right, 'compactCard')
        route.addWidget(label(tr('Маршрут трафика'), 'cardTitle'))
        self.preset_picker = combo(available_presets('ru'))
        self.preset_picker.setMinimumContentsLength(13); self.preset_picker.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.preset_picker.currentIndexChanged.connect(self.preview_preset)
        route.addWidget(self.preset_picker)
        route_actions = QHBoxLayout()
        self.apply_preset_button = button(tr('Применить маршрут'), lambda: self.mutate('preset', {'preset': self.preset_picker.currentData()}), route_actions)
        self.preset_info_button = QToolButton()
        self.preset_info_button.setIcon(icon('info'))
        self.preset_info_button.setAccessibleName(tr('Описание маршрута'))
        self.preset_info_button.setMinimumSize(36, 34)
        self.preset_info_button.clicked.connect(self.describe_preset)
        route_actions.addWidget(self.preset_info_button)
        route.addLayout(route_actions)
        self.active_route = label('', 'caption'); route.addWidget(self.active_route)
        self.lan_summary = label('', 'caption'); route.addWidget(self.lan_summary)
        _, dns = card(right, 'compactCard')
        dns.addWidget(label('DNS', 'cardTitle'))
        self.dns_summary = label(tr('Настройки загружаются…'), 'body'); dns.addWidget(self.dns_summary)
        button(tr('Изменить DNS'), lambda: self.tabs.setCurrentIndex(5), dns, 'text', 'settings')
        _, quick = card(right, 'compactCard')
        self.library_summary = label(tr('Ваши подключения'), 'cardTitle'); quick.addWidget(self.library_summary)
        button(tr('Добавить подключение'), self.import_profiles, quick, '', 'plus')
        button(tr('Обновить подписки'), lambda: self.mutate('subscriptions_update'), quick, 'text', 'refresh')
        right.addStretch()
        row.addLayout(right, 2)
        l.addLayout(row, 1)
        l.addWidget(label(tr('Можно закрыть окно — соединением продолжит управлять фоновый сервис.'), 'caption'))

    def preview_preset(self, *_):
        preset = self.preset_picker.currentData()
        detail = tr(preset_description(preset)) if preset else tr('Выберите новый пресет. Действующий маршрут сохранён.')
        self.preset_info_button.setToolTip(detail)
        self.preset_picker.setToolTip((tr(PRESETS[preset]) + '\n' if preset else '') + detail)
        self.preset_picker.setAccessibleDescription(detail)
        if self.config:
            self.active_route.setVisible(preset != self.config['preset'])
            chosen = next((p for p in self.config['profiles'] if p['id'] == self.config['selected']), {})
            self.apply_preset_button.setEnabled(chosen.get('kind') != 'zerotier' and preset in available_presets(self.config['settings']['country']))

    def describe_preset(self):
        QMessageBox.information(self, tr('Маршрут'), self.preset_info_button.toolTip())

    def toggle_connection(self):
        self.mutate('disconnect' if self.connection_desired else 'connect', {} if self.connection_desired else {'profile_id': self.profile_picker.currentData()})

    def show_status(self, s):
        names = {'disconnected': tr('Отключено'), 'running': tr('VPN включён'), 'connected': tr('Подключено'), 'connecting': tr('Подключение…'), 'authorizing': tr('Ждём авторизацию'), 'error': tr('Ошибка подключения')}
        self.state_title.setText(names.get(s['state'], s['state']))
        details = [s.get('message', '')]
        if s.get('error'): details.append(s['error'])
        if s.get('node_id'): details.append('Node ID: ' + s['node_id'])
        if s.get('addresses'): details.append(', '.join(s['addresses']))
        if s.get('last_probe'): details.append(s['last_probe']['message'])
        self.state_label.setText('\n'.join(x for x in details if x))
        active = bool(s.get('guard'))
        self.guard_badge.setText(tr('Защита включена') if active else tr('Защита выключена'))
        self.guard_badge.setProperty('active', active)
        self.guard_badge.style().unpolish(self.guard_badge); self.guard_badge.style().polish(self.guard_badge)
        self.service_badge.setText(tr('Сервис на связи'))
        self.connection_desired = bool(s.get('desired'))
        self.connect_button.setText(tr('Отключить') if self.connection_desired else tr('Подключить'))
        self.connect_button.setEnabled(bool(s.get('profiles')) or self.connection_desired)
        chosen = next((p for p in s['profiles'] if p['id'] == s['selected']), {})
        self.preset_picker.setEnabled(chosen.get('protocol') != 'zerotier')
        self.apply_preset_button.setEnabled(chosen.get('protocol') != 'zerotier' and self.preset_picker.currentData() in available_presets(self.config['settings']['country']) if self.config else False)
        if self.profile_picker.currentData() != s['selected']:
            self.profile_picker.setCurrentIndex(self.profile_picker.findData(s['selected']))
        if self.config and (s.get('language', 'ru') != language() or s.get('country', 'ru') != self.config['settings'].get('country', 'ru') or s['preset'] != self.config['preset']):
            self.request('configuration', callback=self.loaded, quiet=True)

    def build_profiles(self):
        l = self.page(tr('Профили'))
        row = QHBoxLayout()
        button(tr('Добавить'), self.import_profiles, row, 'primary', 'plus')
        row.addStretch()
        button(tr('Изменить'), self.edit_profile, row, '', 'edit')
        button(tr('Удалить'), lambda: self.delete_selected('profile_delete', self.profiles), row, 'danger', 'delete')
        l.addLayout(row)
        self.profiles = self.collection(tr('Профили подключений')); l.addWidget(self.profiles, 1)
        self.profiles_empty = self.empty(tr('Добавьте первое подключение'), tr('Импортируйте ссылку, конфигурацию или создайте WARP.'))
        l.addWidget(self.profiles_empty, 1)
        _, shortcuts = card(l)
        shortcuts.addWidget(label(tr('Другие подключения'), 'cardTitle'))
        actions = QHBoxLayout()
        button('Cloudflare WARP', self.generate_warp, actions, '', 'warp')
        button(tr('Сеть ZeroTier'), self.add_zerotier, actions, '', 'network')
        shortcuts.addLayout(actions)

    def selected_item(self, widget, kind):
        i = widget.currentRow()
        if self.config and 0 <= i < len(self.config[kind]):
            return self.config[kind][i]
        return None

    def delete_selected(self, method, widget):
        kinds = {"profile_delete": "profiles", "subscription_delete": "subscriptions", "list_delete": "lists"}
        item = self.selected_item(widget, kinds[method])
        if item and QMessageBox.question(self, tr("Удаление"), tr("Удалить «") + item["name"] + "»?") == QMessageBox.Yes:
            self.mutate(method, {"id": item["id"]})

    def import_profiles(self):
        text = area()
        text.setPlaceholderText(tr("Вставьте ссылку, список ссылок, sing-box/Xray JSON, WARP/WireGuard/AmneziaWG .conf, автономный OpenVPN .ovpn или клиентский vpn:// экспорт Amnezia."))
        d = Form(tr("Добавить подключения"), {"text": (tr("Конфигурация"), text)}, self)
        def load():
            path, _ = QFileDialog.getOpenFileName(d, tr("Импортировать"), "", tr("Конфигурации (*.conf *.ovpn *.json *.txt);;Все файлы (*)"))
            if path:
                try:
                    if Path(path).stat().st_size > MAX_BYTES:
                        raise ValueError()
                    text.setPlainText(Path(path).read_text())
                except (OSError, UnicodeError, ValueError):
                    QMessageBox.warning(d, tr("Импорт"), tr("Файл не читается или больше 8 МиБ."))
        button(tr("Открыть файл…"), load, d.layout())
        if d.exec() == QDialog.Accepted:
            self.mutate("import", {"text": text.toPlainText()})

    def edit_profile(self):
        p = self.selected_item(self.profiles, "profiles")
        if not p:
            return
        text = "zerotier://" + p["network_id"] if p["kind"] == "zerotier" else json.dumps(p["outbound"], ensure_ascii=False, indent=2)
        name, config, dns = line(p["name"]), area(text), line(p.get("dns", ""))
        d = Form(tr("Изменить профиль"), {"name": (tr("Название"), name), "dns": (tr("DNS внутри VPN (IP, необязательно)"), dns), "text": (tr("Параметры подключения"), config)}, self)
        if d.exec() == QDialog.Accepted:
            self.mutate("profile_save", {"id": p["id"], "name": name.text(), "dns": dns.text(), "text": config.toPlainText()})

    def generate_warp(self):
        info = QLabel(tr("Создаёт WARP через wgcf. По умолчанию — AmneziaWG с I1 и junk-пакетами, как в конфигурациях warpgen. Ключи и учётная запись сохраняются локально; повторный запуск использует ту же учётную запись. Регистрация обращается к Cloudflare и может быть ограничена сервисом."))
        info.setWordWrap(True)
        terms = QLabel('<a href="' + TERMS + tr('">Условия Cloudflare</a>'))
        terms.setOpenExternalLinks(True)
        consent = QCheckBox(tr("Я принимаю условия Cloudflare для регистрации WARP"))
        mode = combo({"awg": tr("AmneziaWG (с маскировкой)"), "wireguard": tr("WireGuard (обычный)")})
        endpoint = line("")
        endpoint.setPlaceholderText(tr("Необязательно: адрес:порт или [IPv6]:порт"))
        d = Form("Cloudflare WARP", {"info": ("", info), "mode": (tr("Режим"), mode), "endpoint": (tr("Свой endpoint"), endpoint), "terms": ("", terms), "consent": ("", consent)}, self)
        save = d.findChild(QDialogButtonBox).button(QDialogButtonBox.Save)
        save.setText(tr("Создать профиль"))
        save.setEnabled(False)
        consent.toggled.connect(save.setEnabled)
        if d.exec() == QDialog.Accepted:
            self.request("warp_generate", {"accept_terms": consent.isChecked(), "mode": mode.currentData(), "endpoint": endpoint.text()}, lambda result: (self.refresh(), QMessageBox.information(self, "WARP", result["message"])))

    def add_zerotier(self):
        value, ok = QInputDialog.getText(self, "ZeroTier", tr("Network ID (16 символов):"))
        if ok:
            self.mutate("import", {"text": "zerotier://" + value.strip()})

    def build_subscriptions(self):
        l = self.page(tr('Подписки'))
        row = QHBoxLayout()
        button(tr('Добавить'), lambda: self.edit_subscription(), row, 'primary', 'plus')
        row.addStretch()
        button(tr('Изменить'), lambda: self.edit_subscription(self.selected_item(self.subscriptions, 'subscriptions')), row, '', 'edit')
        button(tr('Удалить'), lambda: self.delete_selected('subscription_delete', self.subscriptions), row, 'danger', 'delete')
        l.addLayout(row)
        self.subscriptions = self.collection(tr('Подписки')); l.addWidget(self.subscriptions, 1)
        self.subscriptions_empty = self.empty(tr('Здесь будут ваши подписки'), tr('Добавьте HTTPS-ссылку от провайдера. Параметры HWID задаются при добавлении.'))
        l.addWidget(self.subscriptions_empty, 1)
        row = QHBoxLayout()
        button(tr('Обновить выбранную'), self.update_subscription, row, '', 'refresh')
        button(tr('Обновить все'), lambda: self.mutate('subscriptions_update'), row, 'text')
        l.addLayout(row)
        hwid = disclosure(tr('Идентификатор устройства · общий HWID'), l)
        hwid.addWidget(label(tr('Случайный ID без серийных номеров. Подписка может использовать свой HWID.'), 'caption'))
        self.hwid = line(); self.hwid.setAccessibleName(tr('Общий HWID')); hwid.addWidget(self.hwid)
        row = QHBoxLayout()
        button(tr('Сохранить HWID'), lambda: self.mutate('hwid', {'value': self.hwid.text()}), row, 'primary')
        button(tr('Сгенерировать новый'), lambda: self.mutate('hwid', {'value': ''}), row, 'text', 'refresh')
        hwid.addLayout(row)

    def update_subscription(self):
        sub = self.selected_item(self.subscriptions, "subscriptions")
        if sub:
            self.mutate("subscriptions_update", {"id": sub["id"]})

    def edit_subscription(self, sub=None):
        sub = sub or {}
        name = line(sub.get("name", tr("Подписка")))
        url = line(sub.get("url", ""), secret=True)
        interval = integer(sub.get("interval_hours", 24), 0, 720)
        mode = combo({"none": tr("Не передавать"), "remnawave": "HWID / NekoBox_SF / Remnawave", "header": tr("Указанный HTTP-заголовок"), "query": tr("Указанный параметр URL")})
        mode.setCurrentIndex(mode.findData(sub.get("hwid_mode", "none")))
        hwid_name = line(sub.get("hwid_name", "x-hwid"))
        hwid = line(sub.get("hwid", ""))
        hwid_params = area(sub.get("hwid_params", ""))
        hwid_params.setPlaceholderText(tr("hwid=ваш_id,os=Android,osVersion=16,model=ваша модель\nПусто — HWID и описание Steam Deck. Заполнено — только перечисленные поля."))
        user_agent = line(subscription_agent(sub.get("user_agent")))
        user_agent.setPlaceholderText("Clash Meta: NekoBox/Android/2.00; JSON: sing-box/1.14.3")
        headers = area(json.dumps(sub.get("headers", {}), ensure_ascii=False, indent=2))
        def mode_changed():
            hwid_name.setEnabled(mode.currentData() in {"header", "query"})
            hwid.setEnabled(mode.currentData() != "none")
            hwid_params.setEnabled(mode.currentData() == "remnawave")
        mode.currentIndexChanged.connect(mode_changed)
        mode_changed()
        fields = {"name": (tr("Название"), name), "url": ("HTTPS URL", url), "user_agent": (tr("User-Agent / формат ответа"), user_agent), "interval": (tr("Обновление, ч (0 — вручную)"), interval), "mode": (tr("Передача HWID"), mode), "hwid_name": (tr("Имя заголовка / query-параметра"), hwid_name), "hwid": (tr("Свой HWID (пусто — общий)"), hwid), "hwid_params": (tr("Параметры как в NekoBox_SF"), hwid_params), "headers": (tr("Дополнительные HTTP-заголовки (JSON)"), headers)}
        d = Form(tr("Подписка"), fields, self, advanced=('user_agent', 'hwid_name', 'headers'))
        def visibility_changed():
            selected = mode.currentData()
            d.show_field('hwid', selected != 'none')
            d.show_field('hwid_params', selected == 'remnawave')
            d.show_field('hwid_name', selected in {'header', 'query'})
        mode.currentIndexChanged.connect(visibility_changed)
        visibility_changed()
        d.findChild(QDialogButtonBox).button(QDialogButtonBox.Save).setText(tr("Сохранить и обновить"))
        if d.exec() == QDialog.Accepted:
            try:
                extra = json.loads(headers.toPlainText())
            except ValueError:
                QMessageBox.warning(self, tr("Подписка"), tr("Заголовки должны быть JSON-объектом."))
                return
            def saved(result):
                self.refresh()
                self.request("subscriptions_update", {"id": result["id"]}, lambda _: self.refresh())
            self.request("subscription_save", {"id": sub.get("id"), "name": name.text(), "url": url.text(), "interval_hours": interval.value(), "hwid_mode": mode.currentData(), "hwid_name": hwid_name.text(), "hwid": hwid.text(), "hwid_params": hwid_params.toPlainText(), "user_agent": user_agent.text(), "headers": extra}, saved)

    def build_rules(self):
        l = self.page(tr("Правила"))
        info = label(tr("Правила применяются сверху вниз. Перетаскивайте их, чтобы изменить порядок."), "caption")
        info.setWordWrap(True)
        l.addWidget(info)
        self.rules = self.collection(tr("Правила, сверху вниз"))
        self.rules.setDragDropMode(QListWidget.InternalMove)
        self.rules.setAccessibleName(tr("Правила, сверху вниз"))
        l.addWidget(self.rules)
        self.rules_empty = self.empty(tr('Добавьте своё правило'), tr('Направьте выбранные домены, адреса или приложения через VPN, напрямую или заблокируйте их. Правила выбранного сценария действуют и без пользовательских правил.'))
        l.addWidget(self.rules_empty, 1)
        row = QHBoxLayout()
        button(tr("Добавить"), lambda: self.edit_rule(), row, 'primary', 'plus')
        button(tr("Изменить"), lambda: self.edit_rule(self.rules.currentRow()), row, '', 'edit')
        button(tr("Удалить"), self.remove_rule, row, 'danger', 'delete')
        l.addLayout(row)
        row = QHBoxLayout()
        button(tr("Выше"), lambda: self.move_rule(-1), row)
        button(tr("Ниже"), lambda: self.move_rule(1), row)
        button(tr("Применить порядок"), self.save_rules, row)
        l.addLayout(row)

    def rule_items(self):
        return [self.rules.item(i).data(Qt.UserRole) for i in range(self.rules.count())]

    def show_rules(self, rules):
        self.rules.clear()
        self.rules.setVisible(bool(rules))
        self.rules_empty.setVisible(not rules)
        for r in rules:
            self.rules.addItem(QListWidgetItem(icon("rules"), r["name"] + "\n" + (tr("Включено") if r["enabled"] else tr("Выключено")) + " · " + r["type"] + " → " + {"direct":tr("Напрямую"), "proxy":tr("Через подключение"), "block":tr("Блокировать")}[r["action"]]))
            self.rules.item(self.rules.count() - 1).setData(Qt.UserRole, r)

    def edit_rule(self, index=None):
        if not self.config:
            return
        items = self.rule_items()
        r = items[index] if index is not None and 0 <= index < len(items) else {}
        name = line(r.get("name", tr("Правило")))
        kind = combo({"domain_suffix": tr("Домен и поддомены"), "domain": tr("Точный домен"), "ip_cidr": "IP / CIDR", "list": tr("Набор доменов / IP"), "process_name": tr("Имя процесса (Linux)"), "process_path": tr("Путь процесса (Linux)"), "port": tr("Порт назначения")})
        kind.setCurrentIndex(kind.findData(r.get("type", "domain_suffix")))
        values = area("\n".join(str(x) for x in r.get("values", [])))
        action = combo({"proxy": tr("Через выбранный VPN"), "direct": tr("Напрямую"), "block": tr("Блокировать")})
        action.setCurrentIndex(action.findData(r.get("action", "proxy")))
        enabled = QCheckBox(tr("Правило включено"))
        enabled.setChecked(r.get("enabled", True))
        hints = QLabel(tr("Для набора укажите ID из вкладки «Списки». По одному значению на строку."))
        hints.setWordWrap(True)
        d = Form(tr("Правило"), {"name": (tr("Название"), name), "kind": (tr("Условие"), kind), "values": (tr("Значения"), values), "hint": ("", hints), "action": (tr("Действие"), action), "enabled": ("", enabled)}, self)
        if d.exec() == QDialog.Accepted:
            new = {"name": name.text(), "type": kind.currentData(), "values": values.toPlainText().splitlines(), "action": action.currentData(), "enabled": enabled.isChecked()}
            if r:
                new["id"] = r["id"]
                items[index] = new
            else:
                items.append(new)
            self.mutate("rules_save", {"rules": items})

    def move_rule(self, step):
        row = self.rules.currentRow()
        target = row + step
        if row >= 0 and 0 <= target < self.rules.count():
            item = self.rules.takeItem(row)
            self.rules.insertItem(target, item)
            self.rules.setCurrentRow(target)

    def save_rules(self):
        self.mutate("rules_save", {"rules": self.rule_items()})

    def remove_rule(self):
        row = self.rules.currentRow()
        if row >= 0:
            self.rules.takeItem(row)
            self.save_rules()

    def build_lists(self):
        l = self.page(tr("Списки"))
        self.lists = self.collection(tr("Списки адресов"))
        l.addWidget(self.lists)
        row = QHBoxLayout()
        button(tr("Добавить"), lambda: self.add_list(), row)
        button(tr("Изменить"), lambda: self.add_list(self.selected_item(self.lists, "lists")), row)
        button(tr("Обновить выбранный"), self.update_list, row)
        button(tr("Удалить"), lambda: self.delete_selected("list_delete", self.lists), row)
        l.addLayout(row)
        button(tr("Скопировать ID"), self.copy_list_id, l)
        hint = QLabel(tr("Региональные списки — ориентир для маршрутизации, а не точная карта блокировок. Они скачиваются при применении пресета. Пользовательские правила сохраняются при смене страны и сценария."))
        hint.setWordWrap(True)
        l.addWidget(hint)

    def add_list(self, item=None, contents=None):
        item = item or {}
        if item.get('id') in BUILTIN_LISTS:
            QMessageBox.information(self, tr("Списки"), tr("Для изменения встроенного списка создайте пользовательскую копию."))
            return
        existing = ""
        if item.get("path") and not item.get("url"):
            if contents is None:
                self.request("list_content", {"id": item["id"]}, callback=lambda data: self.add_list(item, data["content"]))
                return
            existing = contents
        name, url, content = line(item.get("name", tr("Мой список"))), line(item.get("url", "")), area(existing)
        fmt = combo({"text": tr("Текст: домен или CIDR на строку"), "source": "sing-box source JSON", "srs": tr("sing-box SRS по HTTPS")})
        fmt.setCurrentIndex(fmt.findData("source" if existing else item.get("format", "text")))
        d = Form(tr("Добавить список"), {"name": (tr("Название"), name), "url": (tr("HTTPS URL (необязательно)"), url), "format": (tr("Формат"), fmt), "content": (tr("Или содержимое списка"), content)}, self)
        if d.exec() == QDialog.Accepted:
            self.mutate("list_save", {"id": item.get("id"), "name": name.text(), "url": url.text(), "format": fmt.currentData(), **({"content": content.toPlainText()} if content.toPlainText().strip() else {})})

    def update_list(self):
        item = self.selected_item(self.lists, "lists")
        if item:
            self.mutate("lists_update", {"id": item["id"]})

    def copy_list_id(self):
        item = self.selected_item(self.lists, "lists")
        if item:
            QApplication.clipboard().setText(item["id"])

    def build_settings(self):
        l = self.page(tr("Настройки"))
        _, preferences = card(l)
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.WrapLongRows)
        self.language_picker = combo({'ru': 'Русский', 'en': 'English'})
        self.country_picker = combo({key: tr(name) for key, name in COUNTRIES.items()})
        self.language_picker.activated.connect(lambda _: self.mutate('preferences', {'language': self.language_picker.currentData()}))
        self.country_picker.activated.connect(lambda _: self.mutate('preferences', {'country': self.country_picker.currentData()}))
        form.addRow(tr('Язык интерфейса'), self.language_picker)
        form.addRow(tr('Страна маршрутизации'), self.country_picker)
        preferences.addLayout(form)
        preferences.addWidget(label(tr('Язык и страна независимы. Страна меняет доступные пресеты, а не VPN-сервер. Выберите и примените маршрут на странице подключения; действующий маршрут сохраняется до применения.'), 'caption'))
        self.setting_widgets = {}
        _, protection = card(l)
        protection.addWidget(label(tr('Защита и локальная сеть'), 'cardTitle'))
        for key, name in {"auto_connect": tr("Подключать при загрузке Steam Deck"), "kill_switch": tr("Блокировать прямой выход при сбое VPN"), "lan": tr("Доступ к локальной сети и Remote Play"), "ipv6": tr("Разрешить IPv6 через правила")}.items():
            w = Switch(name)
            protection.addWidget(w)
            self.setting_widgets[key] = w
        protection.addWidget(label(tr('Автоподключение выключено по умолчанию. Восстановление уже включённого VPN после сбоя и сна работает независимо.'), 'caption'))
        dns_row = QHBoxLayout(); dns_row.setSpacing(16)
        for key, name in [("dns_proxy", tr("DNS через VPN")), ("dns_direct", tr("DNS прямых запросов"))]:
            frame, body = card()
            body.addWidget(label(name, 'cardTitle'))
            body.addWidget(label(tr('Защищённый DNS · DoH / DoT'), 'caption'))
            w = DNSSelector()
            body.addWidget(w)
            self.setting_widgets[key] = w
            dns_row.addWidget(frame, 1)
        l.addLayout(dns_row)
        l.addWidget(label(tr('Можно выбрать готовый сервер или ввести свой адрес. DNS из профиля WG/AWG имеет приоритет для запросов через VPN. При ошибке DoH/DoT перехода на обычный DNS нет.'), 'caption'))
        advanced = disclosure(tr('Параметры сети и восстановления'), l)
        form = QFormLayout(); form.setVerticalSpacing(12)
        form.setRowWrapPolicy(QFormLayout.WrapLongRows)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        advanced.addLayout(form)
        for key, name, low, high in [("mtu", "MTU TUN", 1280, 9000), ("reconnect_seconds", tr("Повтор подключения, с"), 5, 300), ("list_update_hours", tr("Обновление списков, ч"), 1, 720)]:
            w = integer(low, low, high)
            w.setAccessibleName(name)
            form.addRow(name, w)
            self.setting_widgets[key] = w
        w = line()
        form.addRow(tr("Начальный DNS (UDP, IP)"), w)
        self.setting_widgets["dns_bootstrap"] = w
        advanced.addWidget(label(tr('Начальный DNS разрешает имена серверов до подключения и локальные .lan / .local / .home.arpa.'), 'caption'))
        w = combo({"proxy": "VPN", "direct": tr("Напрямую"), "block": tr("Блокировать")})
        form.addRow(tr("Маршрут в «Моих правилах»"), w)
        self.setting_widgets["default_action"] = w
        row = QHBoxLayout()
        button(tr("Сохранить и применить"), self.save_settings, row, 'primary')
        row.addStretch()
        button(tr("О программе"), lambda: QMessageBox.information(self, "Helmsman", tr(f"Helmsman {VERSION}\nGPL-3.0-only, без гарантий. Исходники и лицензии компонентов включены в архив релиза.\nСетевые движки: SagerNet/sing-box, Throne/sing-box, Xray-core, wgcf и ZeroTier Agent (MPL-2.0, без nonfree controller).\nhttps://github.com/ISAIandCO/Helmsman")), row, 'text')
        l.addLayout(row)
        l.addStretch()

    def save_settings(self):
        result = {}
        for key, w in self.setting_widgets.items():
            result[key] = w.isChecked() if isinstance(w, QCheckBox) else w.value() if isinstance(w, (QSpinBox, DNSSelector)) else w.currentData() if isinstance(w, QComboBox) else w.text()
        self.mutate("settings_save", {"settings": result})

    def build_diagnostics(self):
        l = self.page(tr("Диагностика"))
        l.addWidget(label(tr('Отчёт исключает ключи и содержимое подписок. Его можно скопировать для обращения с ошибкой.'), 'caption'))
        self.diagnostics = area()
        self.diagnostics.setReadOnly(True)
        l.addWidget(self.diagnostics)
        row = QHBoxLayout()
        button(tr("Собрать отчёт"), lambda: self.request("diagnostics", callback=lambda r: self.diagnostics.setPlainText(json.dumps(r, ensure_ascii=False, indent=2))), row, 'primary', 'refresh')
        button(tr('Скопировать'), lambda: QApplication.clipboard().setText(self.diagnostics.toPlainText()), row)
        row.addStretch(); l.addLayout(row)

    def loaded(self, config):
        target_language = config['settings'].get('language', 'ru')
        if language() != target_language:
            index = self.tabs.currentIndex()
            set_language(target_language)
            self.build_ui()
            self.tabs.setCurrentIndex(index)
        selected = {kind: (self.selected_item(getattr(self, kind), kind) or {}).get('id') for kind in ('profiles', 'subscriptions', 'lists')}
        self.config = config
        self.profiles.clear()
        self.profile_picker.clear()
        for p in config["profiles"]:
            t = "ZeroTier" if p["kind"] == "zerotier" else "AmneziaWG" if p["outbound"].get("amnezia_wg") else p["outbound"]["type"].upper() + (" / XHTTP" if is_xhttp(p) else "") + (" / mux" if 'xray_mux' in p['outbound'] else '')
            self.profiles.addItem(QListWidgetItem(icon('network' if p['kind'] == 'zerotier' else 'profiles'), p["name"] + "\n" + t))
            self.profile_picker.addItem(p["name"] + " · " + t, p["id"])
        self.profiles.setVisible(bool(config['profiles']))
        self.profiles_empty.setVisible(not config['profiles'])
        self.profile_picker.setCurrentIndex(self.profile_picker.findData(config["selected"]))
        country = config['settings'].get('country', 'ru')
        self.language_picker.setCurrentIndex(self.language_picker.findData(target_language))
        self.country_picker.setCurrentIndex(self.country_picker.findData(country))
        self.preset_picker.blockSignals(True)
        self.preset_picker.clear()
        for key, name in available_presets(country).items():
            self.preset_picker.addItem(tr(name), key)
        self.preset_picker.setCurrentIndex(self.preset_picker.findData(config['preset']))
        self.preset_picker.blockSignals(False)
        self.active_route.setText(tr('Действует: ') + tr(PRESETS[config['preset']]))
        self.preview_preset()
        self.subscriptions.clear()
        for s in config["subscriptions"]:
            detail = translate_message(s.get('error', ''), language()) or (tr('Обновлено ') + datetime.fromtimestamp(s['last_update']).strftime('%d.%m %H:%M') if s.get('last_update') else tr('Ещё не обновлялась'))
            self.subscriptions.addItem(QListWidgetItem(icon('subscriptions'), s['name'] + '\n' + detail))
        self.subscriptions.setVisible(bool(config['subscriptions']))
        self.subscriptions_empty.setVisible(not config['subscriptions'])
        self.hwid.setText(config["hwid"])
        self.show_rules(config["rules"])
        self.lists.clear()
        for item in config["lists"]:
            when = datetime.fromtimestamp(item["last_update"]).strftime("%d.%m.%Y %H:%M") if item.get("last_update") else tr("Не загружен")
            self.lists.addItem(QListWidgetItem(icon('lists'), (tr(BUILTIN_LISTS[item['id']][0]) if item['id'] in BUILTIN_LISTS else item['name']) + '\n' + (translate_message(item.get('error', ''), language()) or when)))
        for kind, previous in selected.items():
            view = getattr(self, kind)
            index = next((i for i, item in enumerate(config[kind]) if item['id'] == previous), 0)
            view.setCurrentRow(index if view.count() else -1)
        self.library_summary.setText(tr(f"Подключений: {len(config['profiles'])}"))
        self.lan_summary.setText(tr('Локальная сеть доступна напрямую') if config['settings']['lan'] else tr('Локальная сеть подчиняется правилам'))
        settings = config['settings']
        chosen = next((p for p in config['profiles'] if p['id'] == config['selected']), {})
        self.dns_summary.setText(tr('Через VPN: ') + (chosen.get('dns') or urlsplit(resolver_url(settings['dns_proxy'])).hostname or '') + tr('\nНапрямую: ') + (urlsplit(resolver_url(settings['dns_direct'])).hostname or ''))
        for key, w in self.setting_widgets.items():
            value = config["settings"][key]
            if isinstance(w, QCheckBox):
                w.setChecked(value)
            elif isinstance(w, QSpinBox):
                w.setValue(int(value))
            elif isinstance(w, DNSSelector):
                w.set_value(value)
            elif isinstance(w, QComboBox):
                w.setCurrentIndex(w.findData(value))
            else:
                w.setText(str(value))
        self.poll()

    def closeEvent(self, event):
        if self.workers:
            self.statusBar().showMessage(tr("Дождитесь завершения запроса к сервису."))
            event.ignore()
        else:
            event.accept()


def main():
    if os.environ.get('XDG_SESSION_TYPE') == 'wayland' and os.environ.get('WAYLAND_DISPLAY'):
        os.environ.setdefault('QT_QPA_PLATFORM', 'wayland;xcb')
    app = QApplication(sys.argv)
    theme(app)
    window = Window()
    window.show()
    if "--smoke-test" in sys.argv:
        print("Helmsman Qt platform: " + app.platformName(), flush=True)
        QTimer.singleShot(700, app.quit)
    app.exec()


if __name__ == "__main__":
    main()
