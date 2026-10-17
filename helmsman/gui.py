"""Native Qt desktop client. All network operations belong to the service."""
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from PySide6.QtCore import QThread, QTimer, Signal, Qt, QSize
from PySide6.QtWidgets import (QApplication, QButtonGroup, QCheckBox, QFrame, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSpinBox, QStackedWidget, QScroller, QVBoxLayout, QWidget)

from .common import MAX_BYTES, PRESETS, UserError, VERSION
from .dns import DNS_PRESETS, resolver_url
from .rpc import call
from .subscriptions import SUBSCRIPTION_AGENT
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
        c.addItem(text, key)
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
            pane = disclosure('Дополнительные настройки', body)
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
        buttons.button(QDialogButtonBox.Save).setText('Сохранить')
        buttons.button(QDialogButtonBox.Save).setProperty('variant', 'primary')
        buttons.button(QDialogButtonBox.Save).style().unpolish(buttons.button(QDialogButtonBox.Save))
        buttons.button(QDialogButtonBox.Save).style().polish(buttons.button(QDialogButtonBox.Save))
        buttons.button(QDialogButtonBox.Cancel).setText('Отмена')
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
        self.picker.addItem("Свой сервер…", "")
        self.address = line()
        self.address.setPlaceholderText("https://сервер/dns-query или tls://сервер:853")
        self.address.setAccessibleName("Адрес DNS DoH или DoT")
        self.picker.setAccessibleName("Готовый DNS или свой сервер")
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
        self.resize(1180, 750)
        self.setMinimumSize(960, 600)
        self.setWindowIcon(icon('compass', COLORS['primary'], 64))
        self.config = None
        self.workers = set()
        self.busy = False
        self.connection_desired = False
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
        self.service_badge = label('Ожидание сервиса', 'badge')
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
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll)
        self.timer.start(3000)
        self.refresh()

    def page(self, name):
        descriptions = {
            'Подключение': ('Ваше соединение', 'Выберите подключение и маршрут для интернета.'),
            'Профили': ('Подключения', 'Ваши серверы и виртуальные сети.'),
            'Подписки': ('Подписки', 'Управляйте списками серверов и обновлениями.'),
            'Правила': ('Маршрутизация', 'Решайте, какой трафик идёт через подключение.'),
            'Списки': ('Списки адресов', 'Домены и IP для ваших правил.'),
            'Настройки': ('Настройки', 'Защита соединения, DNS и поведение сервиса.'),
            'Диагностика': ('Диагностика', 'Состояние сервиса и последние события.'),
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
            self.statusBar().showMessage("Выполняется…")
        def success(result):
            if not quiet:
                self.busy = False
                self.statusBar().showMessage("Готово", 3000)
            if callback:
                callback(result)
        def failure(message):
            if not quiet:
                self.busy = False
                QMessageBox.warning(self, "Helmsman", message)
            self.statusBar().showMessage(message, 10000)
            if method in {'status', 'configuration'}:
                self.service_badge.setText('Сервис недоступен')
                self.state_title.setText('Нет связи с сервисом')
                self.state_label.setText(message)
                self.guard_badge.setText('Состояние неизвестно')
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
        l = self.page('Подключение')
        row = QHBoxLayout(); row.setSpacing(18)
        hero, body = card(role='heroCard')
        top = QHBoxLayout()
        top.addWidget(label('ПОДКЛЮЧЕНИЕ', 'eyebrow')); top.addStretch()
        self.guard_badge = label('Защита выключена', 'badge'); top.addWidget(self.guard_badge)
        body.addLayout(top)
        mark = QLabel(); mark.setPixmap(icon('power', COLORS['primary'], 64).pixmap(64,64)); body.addWidget(mark)
        self.state_title = label('Добро пожаловать', 'stateTitle'); body.addWidget(self.state_title)
        self.state_label = label('Ожидание сервиса…', 'body'); self.state_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        body.addWidget(self.state_label)
        body.addSpacing(12)
        body.addWidget(label('Выбранное подключение', 'caption'))
        self.profile_picker = QComboBox(); self.profile_picker.setAccessibleName('Выбранное подключение')
        self.profile_picker.setMinimumContentsLength(16); self.profile_picker.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.profile_picker.activated.connect(lambda _: self.mutate('select', {'profile_id': self.profile_picker.currentData()}))
        body.addWidget(self.profile_picker)
        self.connect_button = button('Подключить', self.toggle_connection, body, 'connect', 'power')
        self.connect_button.setEnabled(False)
        button('Проверить подключение', lambda: self.request('probe', callback=lambda r: QMessageBox.information(self, 'Проверка', r['message'])), body, 'text', 'diagnostics')
        body.addStretch()
        row.addWidget(hero, 3)
        right = QVBoxLayout(); right.setSpacing(16)
        _, route = card(right)
        route.addWidget(label('Маршрут трафика', 'cardTitle'))
        self.preset_picker = combo(PRESETS)
        self.preset_picker.setMinimumContentsLength(13); self.preset_picker.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.preset_picker.activated.connect(lambda _: self.mutate('preset', {'preset': self.preset_picker.currentData()}))
        route.addWidget(self.preset_picker)
        self.lan_summary = label('', 'caption'); route.addWidget(self.lan_summary)
        button('Настроить правила', lambda: self.tabs.setCurrentIndex(3), route, 'text', 'rules')
        _, dns = card(right)
        dns.addWidget(label('DNS', 'cardTitle'))
        self.dns_summary = label('Настройки загружаются…', 'body'); dns.addWidget(self.dns_summary)
        button('Изменить DNS', lambda: self.tabs.setCurrentIndex(5), dns, 'text', 'settings')
        _, quick = card(right)
        self.library_summary = label('Ваши подключения', 'cardTitle'); quick.addWidget(self.library_summary)
        button('Добавить подключение', self.import_profiles, quick, '', 'plus')
        button('Обновить подписки', lambda: self.mutate('subscriptions_update'), quick, 'text', 'refresh')
        right.addStretch()
        row.addLayout(right, 2)
        l.addLayout(row, 1)
        l.addWidget(label('Можно закрыть окно — соединением продолжит управлять фоновый сервис.', 'caption'))

    def toggle_connection(self):
        self.mutate('disconnect' if self.connection_desired else 'connect', {} if self.connection_desired else {'profile_id': self.profile_picker.currentData()})

    def show_status(self, s):
        names = {'disconnected': 'Отключено', 'running': 'VPN включён', 'connected': 'Подключено', 'connecting': 'Подключение…', 'authorizing': 'Ждём авторизацию', 'error': 'Ошибка подключения'}
        self.state_title.setText(names.get(s['state'], s['state']))
        details = [s.get('message', '')]
        if s.get('error'): details.append(s['error'])
        if s.get('node_id'): details.append('Node ID: ' + s['node_id'])
        if s.get('addresses'): details.append(', '.join(s['addresses']))
        if s.get('last_probe'): details.append(s['last_probe']['message'])
        self.state_label.setText('\n'.join(x for x in details if x))
        active = bool(s.get('guard'))
        self.guard_badge.setText('Защита включена' if active else 'Защита выключена')
        self.guard_badge.setProperty('active', active)
        self.guard_badge.style().unpolish(self.guard_badge); self.guard_badge.style().polish(self.guard_badge)
        self.service_badge.setText('Сервис на связи')
        self.connection_desired = bool(s.get('desired'))
        self.connect_button.setText('Отключить' if self.connection_desired else 'Подключить')
        self.connect_button.setEnabled(bool(s.get('profiles')) or self.connection_desired)
        chosen = next((p for p in s['profiles'] if p['id'] == s['selected']), {})
        self.preset_picker.setEnabled(chosen.get('protocol') != 'zerotier')
        if self.profile_picker.currentData() != s['selected']:
            self.profile_picker.setCurrentIndex(self.profile_picker.findData(s['selected']))
        self.preset_picker.setCurrentIndex(self.preset_picker.findData(s['preset']))

    def build_profiles(self):
        l = self.page('Профили')
        row = QHBoxLayout()
        button('Добавить', self.import_profiles, row, 'primary', 'plus')
        row.addStretch()
        button('Изменить', self.edit_profile, row, '', 'edit')
        button('Удалить', lambda: self.delete_selected('profile_delete', self.profiles), row, 'danger', 'delete')
        l.addLayout(row)
        self.profiles = self.collection('Профили подключений'); l.addWidget(self.profiles, 1)
        self.profiles_empty = self.empty('Добавьте первое подключение', 'Импортируйте ссылку, конфигурацию или создайте WARP.')
        l.addWidget(self.profiles_empty, 1)
        _, shortcuts = card(l)
        shortcuts.addWidget(label('Другие подключения', 'cardTitle'))
        actions = QHBoxLayout()
        button('Cloudflare WARP', self.generate_warp, actions, '', 'warp')
        button('Сеть ZeroTier', self.add_zerotier, actions, '', 'network')
        shortcuts.addLayout(actions)

    def selected_item(self, widget, kind):
        i = widget.currentRow()
        if self.config and 0 <= i < len(self.config[kind]):
            return self.config[kind][i]
        return None

    def delete_selected(self, method, widget):
        kinds = {"profile_delete": "profiles", "subscription_delete": "subscriptions", "list_delete": "lists"}
        item = self.selected_item(widget, kinds[method])
        if item and QMessageBox.question(self, "Удаление", "Удалить «" + item["name"] + "»?") == QMessageBox.Yes:
            self.mutate(method, {"id": item["id"]})

    def import_profiles(self):
        text = area()
        text.setPlaceholderText("Вставьте ссылку, список ссылок, sing-box/Xray JSON, WARP/WireGuard/AmneziaWG .conf, автономный OpenVPN .ovpn или клиентский vpn:// экспорт Amnezia.")
        d = Form("Добавить подключения", {"text": ("Конфигурация", text)}, self)
        def load():
            path, _ = QFileDialog.getOpenFileName(d, "Импортировать", "", "Конфигурации (*.conf *.ovpn *.json *.txt);;Все файлы (*)")
            if path:
                try:
                    if Path(path).stat().st_size > MAX_BYTES:
                        raise ValueError()
                    text.setPlainText(Path(path).read_text())
                except (OSError, UnicodeError, ValueError):
                    QMessageBox.warning(d, "Импорт", "Файл не читается или больше 8 МиБ.")
        button("Открыть файл…", load, d.layout())
        if d.exec() == QDialog.Accepted:
            self.mutate("import", {"text": text.toPlainText()})

    def edit_profile(self):
        p = self.selected_item(self.profiles, "profiles")
        if not p:
            return
        text = "zerotier://" + p["network_id"] if p["kind"] == "zerotier" else json.dumps(p["outbound"], ensure_ascii=False, indent=2)
        name, config, dns = line(p["name"]), area(text), line(p.get("dns", ""))
        d = Form("Изменить профиль", {"name": ("Название", name), "dns": ("DNS внутри VPN (IP, необязательно)", dns), "text": ("Параметры подключения", config)}, self)
        if d.exec() == QDialog.Accepted:
            self.mutate("profile_save", {"id": p["id"], "name": name.text(), "dns": dns.text(), "text": config.toPlainText()})

    def generate_warp(self):
        info = QLabel("Создаёт WARP через wgcf. По умолчанию — AmneziaWG с I1 и junk-пакетами, как в конфигурациях warpgen. Ключи и учётная запись сохраняются локально; повторный запуск использует ту же учётную запись. Регистрация обращается к Cloudflare и может быть ограничена сервисом.")
        info.setWordWrap(True)
        terms = QLabel('<a href="' + TERMS + '">Условия Cloudflare</a>')
        terms.setOpenExternalLinks(True)
        consent = QCheckBox("Я принимаю условия Cloudflare для регистрации WARP")
        mode = combo({"awg": "AmneziaWG (с маскировкой)", "wireguard": "WireGuard (обычный)"})
        endpoint = line("")
        endpoint.setPlaceholderText("Необязательно: адрес:порт или [IPv6]:порт")
        d = Form("Cloudflare WARP", {"info": ("", info), "mode": ("Режим", mode), "endpoint": ("Свой endpoint", endpoint), "terms": ("", terms), "consent": ("", consent)}, self)
        save = d.findChild(QDialogButtonBox).button(QDialogButtonBox.Save)
        save.setText("Создать профиль")
        save.setEnabled(False)
        consent.toggled.connect(save.setEnabled)
        if d.exec() == QDialog.Accepted:
            self.request("warp_generate", {"accept_terms": consent.isChecked(), "mode": mode.currentData(), "endpoint": endpoint.text()}, lambda result: (self.refresh(), QMessageBox.information(self, "WARP", result["message"])))

    def add_zerotier(self):
        value, ok = QInputDialog.getText(self, "ZeroTier", "Network ID (16 символов):")
        if ok:
            self.mutate("import", {"text": "zerotier://" + value.strip()})

    def build_subscriptions(self):
        l = self.page('Подписки')
        row = QHBoxLayout()
        button('Добавить', lambda: self.edit_subscription(), row, 'primary', 'plus')
        row.addStretch()
        button('Изменить', lambda: self.edit_subscription(self.selected_item(self.subscriptions, 'subscriptions')), row, '', 'edit')
        button('Удалить', lambda: self.delete_selected('subscription_delete', self.subscriptions), row, 'danger', 'delete')
        l.addLayout(row)
        self.subscriptions = self.collection('Подписки'); l.addWidget(self.subscriptions, 1)
        self.subscriptions_empty = self.empty('Здесь будут ваши подписки', 'Добавьте HTTPS-ссылку от провайдера. Параметры HWID задаются при добавлении.')
        l.addWidget(self.subscriptions_empty, 1)
        row = QHBoxLayout()
        button('Обновить выбранную', self.update_subscription, row, '', 'refresh')
        button('Обновить все', lambda: self.mutate('subscriptions_update'), row, 'text')
        l.addLayout(row)
        hwid = disclosure('Идентификатор устройства · общий HWID', l)
        hwid.addWidget(label('Случайный ID без серийных номеров. Подписка может использовать свой HWID.', 'caption'))
        self.hwid = line(); self.hwid.setAccessibleName('Общий HWID'); hwid.addWidget(self.hwid)
        row = QHBoxLayout()
        button('Сохранить HWID', lambda: self.mutate('hwid', {'value': self.hwid.text()}), row, 'primary')
        button('Сгенерировать новый', lambda: self.mutate('hwid', {'value': ''}), row, 'text', 'refresh')
        hwid.addLayout(row)

    def update_subscription(self):
        sub = self.selected_item(self.subscriptions, "subscriptions")
        if sub:
            self.mutate("subscriptions_update", {"id": sub["id"]})

    def edit_subscription(self, sub=None):
        sub = sub or {}
        name = line(sub.get("name", "Подписка"))
        url = line(sub.get("url", ""), secret=True)
        interval = integer(sub.get("interval_hours", 24), 0, 720)
        mode = combo({"none": "Не передавать", "remnawave": "HWID / NekoBox_SF / Remnawave", "header": "Указанный HTTP-заголовок", "query": "Указанный параметр URL"})
        mode.setCurrentIndex(mode.findData(sub.get("hwid_mode", "none")))
        hwid_name = line(sub.get("hwid_name", "x-hwid"))
        hwid = line(sub.get("hwid", ""))
        hwid_params = area(sub.get("hwid_params", ""))
        hwid_params.setPlaceholderText("hwid=ваш_id,os=Android,osVersion=16,model=ваша модель\nПусто — HWID и описание Steam Deck. Заполнено — только перечисленные поля.")
        user_agent = line(sub.get("user_agent", SUBSCRIPTION_AGENT))
        user_agent.setPlaceholderText("V2Ray: v2rayNG/1.10.5; JSON: sing-box/1.14.3")
        headers = area(json.dumps(sub.get("headers", {}), ensure_ascii=False, indent=2))
        def mode_changed():
            hwid_name.setEnabled(mode.currentData() in {"header", "query"})
            hwid.setEnabled(mode.currentData() != "none")
            hwid_params.setEnabled(mode.currentData() == "remnawave")
        mode.currentIndexChanged.connect(mode_changed)
        mode_changed()
        fields = {"name": ("Название", name), "url": ("HTTPS URL", url), "user_agent": ("User-Agent / формат ответа", user_agent), "interval": ("Обновление, ч (0 — вручную)", interval), "mode": ("Передача HWID", mode), "hwid_name": ("Имя заголовка / query-параметра", hwid_name), "hwid": ("Свой HWID (пусто — общий)", hwid), "hwid_params": ("Параметры как в NekoBox_SF", hwid_params), "headers": ("Дополнительные HTTP-заголовки (JSON)", headers)}
        d = Form("Подписка", fields, self, advanced=('user_agent', 'hwid_name', 'headers'))
        def visibility_changed():
            selected = mode.currentData()
            d.show_field('hwid', selected != 'none')
            d.show_field('hwid_params', selected == 'remnawave')
            d.show_field('hwid_name', selected in {'header', 'query'})
        mode.currentIndexChanged.connect(visibility_changed)
        visibility_changed()
        d.findChild(QDialogButtonBox).button(QDialogButtonBox.Save).setText("Сохранить и обновить")
        if d.exec() == QDialog.Accepted:
            try:
                extra = json.loads(headers.toPlainText())
            except ValueError:
                QMessageBox.warning(self, "Подписка", "Заголовки должны быть JSON-объектом.")
                return
            def saved(result):
                self.refresh()
                self.request("subscriptions_update", {"id": result["id"]}, lambda _: self.refresh())
            self.request("subscription_save", {"id": sub.get("id"), "name": name.text(), "url": url.text(), "interval_hours": interval.value(), "hwid_mode": mode.currentData(), "hwid_name": hwid_name.text(), "hwid": hwid.text(), "hwid_params": hwid_params.toPlainText(), "user_agent": user_agent.text(), "headers": extra}, saved)

    def build_rules(self):
        l = self.page("Правила")
        info = label("Правила применяются сверху вниз. Перетаскивайте их, чтобы изменить порядок.", "caption")
        info.setWordWrap(True)
        l.addWidget(info)
        self.rules = self.collection("Правила, сверху вниз")
        self.rules.setDragDropMode(QListWidget.InternalMove)
        self.rules.setAccessibleName("Правила, сверху вниз")
        l.addWidget(self.rules)
        self.rules_empty = self.empty('Добавьте своё правило', 'Направьте выбранные домены, адреса или приложения через VPN, напрямую или заблокируйте их. Правила выбранного сценария действуют и без пользовательских правил.')
        l.addWidget(self.rules_empty, 1)
        row = QHBoxLayout()
        button("Добавить", lambda: self.edit_rule(), row, 'primary', 'plus')
        button("Изменить", lambda: self.edit_rule(self.rules.currentRow()), row, '', 'edit')
        button("Удалить", self.remove_rule, row, 'danger', 'delete')
        l.addLayout(row)
        row = QHBoxLayout()
        button("Выше", lambda: self.move_rule(-1), row)
        button("Ниже", lambda: self.move_rule(1), row)
        button("Применить порядок", self.save_rules, row)
        l.addLayout(row)

    def rule_items(self):
        return [self.rules.item(i).data(Qt.UserRole) for i in range(self.rules.count())]

    def show_rules(self, rules):
        self.rules.clear()
        self.rules.setVisible(bool(rules))
        self.rules_empty.setVisible(not rules)
        for r in rules:
            self.rules.addItem(QListWidgetItem(icon("rules"), r["name"] + "\n" + ("Включено" if r["enabled"] else "Выключено") + " · " + r["type"] + " → " + {"direct":"Напрямую", "proxy":"Через подключение", "block":"Блокировать"}[r["action"]]))
            self.rules.item(self.rules.count() - 1).setData(Qt.UserRole, r)

    def edit_rule(self, index=None):
        if not self.config:
            return
        items = self.rule_items()
        r = items[index] if index is not None and 0 <= index < len(items) else {}
        name = line(r.get("name", "Правило"))
        kind = combo({"domain_suffix": "Домен и поддомены", "domain": "Точный домен", "ip_cidr": "IP / CIDR", "list": "Набор доменов / IP", "process_name": "Имя процесса (Linux)", "process_path": "Путь процесса (Linux)", "port": "Порт назначения"})
        kind.setCurrentIndex(kind.findData(r.get("type", "domain_suffix")))
        values = area("\n".join(str(x) for x in r.get("values", [])))
        action = combo({"proxy": "Через выбранный VPN", "direct": "Напрямую", "block": "Блокировать"})
        action.setCurrentIndex(action.findData(r.get("action", "proxy")))
        enabled = QCheckBox("Правило включено")
        enabled.setChecked(r.get("enabled", True))
        hints = QLabel("Для набора укажите ID из вкладки «Списки». По одному значению на строку.")
        hints.setWordWrap(True)
        d = Form("Правило", {"name": ("Название", name), "kind": ("Условие", kind), "values": ("Значения", values), "hint": ("", hints), "action": ("Действие", action), "enabled": ("", enabled)}, self)
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
        l = self.page("Списки")
        self.lists = self.collection("Списки адресов")
        l.addWidget(self.lists)
        row = QHBoxLayout()
        button("Добавить", lambda: self.add_list(), row)
        button("Изменить", lambda: self.add_list(self.selected_item(self.lists, "lists")), row)
        button("Обновить выбранный", self.update_list, row)
        button("Удалить", lambda: self.delete_selected("list_delete", self.lists), row)
        l.addLayout(row)
        button("Скопировать ID", self.copy_list_id, l)
        hint = QLabel("Общественные российские списки — ориентир для маршрутизации, а не точная карта блокировок. До загрузки пресета они не скачиваются. Пользовательские правила сохраняются при смене сценария.")
        hint.setWordWrap(True)
        l.addWidget(hint)

    def add_list(self, item=None, contents=None):
        item = item or {}
        if item.get("id", "").startswith("ru-"):
            QMessageBox.information(self, "Списки", "Для изменения встроенного списка создайте пользовательскую копию.")
            return
        existing = ""
        if item.get("path") and not item.get("url"):
            if contents is None:
                self.request("list_content", {"id": item["id"]}, callback=lambda data: self.add_list(item, data["content"]))
                return
            existing = contents
        name, url, content = line(item.get("name", "Мой список")), line(item.get("url", "")), area(existing)
        fmt = combo({"text": "Текст: домен или CIDR на строку", "source": "sing-box source JSON", "srs": "sing-box SRS по HTTPS"})
        fmt.setCurrentIndex(fmt.findData("source" if existing else item.get("format", "text")))
        d = Form("Добавить список", {"name": ("Название", name), "url": ("HTTPS URL (необязательно)", url), "format": ("Формат", fmt), "content": ("Или содержимое списка", content)}, self)
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
        l = self.page("Настройки")
        self.setting_widgets = {}
        _, protection = card(l)
        protection.addWidget(label('Защита и локальная сеть', 'cardTitle'))
        for key, name in {"kill_switch": "Блокировать прямой выход при сбое VPN", "lan": "Доступ к локальной сети и Remote Play", "ipv6": "Разрешить IPv6 через правила"}.items():
            w = Switch(name)
            protection.addWidget(w)
            self.setting_widgets[key] = w
        dns_row = QHBoxLayout(); dns_row.setSpacing(16)
        for key, name in [("dns_proxy", "DNS через VPN"), ("dns_direct", "DNS прямых запросов")]:
            frame, body = card()
            body.addWidget(label(name, 'cardTitle'))
            body.addWidget(label('Защищённый DNS · DoH / DoT', 'caption'))
            w = DNSSelector()
            body.addWidget(w)
            self.setting_widgets[key] = w
            dns_row.addWidget(frame, 1)
        l.addLayout(dns_row)
        l.addWidget(label('Можно выбрать готовый сервер или ввести свой адрес. DNS из профиля WG/AWG имеет приоритет для запросов через VPN. При ошибке DoH/DoT перехода на обычный DNS нет.', 'caption'))
        advanced = disclosure('Параметры сети и восстановления', l)
        form = QFormLayout(); form.setVerticalSpacing(12)
        form.setRowWrapPolicy(QFormLayout.WrapLongRows)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        advanced.addLayout(form)
        for key, name, low, high in [("mtu", "MTU TUN", 1280, 9000), ("reconnect_seconds", "Повтор подключения, с", 5, 300), ("list_update_hours", "Обновление списков, ч", 1, 720)]:
            w = integer(low, low, high)
            w.setAccessibleName(name)
            form.addRow(name, w)
            self.setting_widgets[key] = w
        w = line()
        form.addRow("Начальный DNS (UDP, IP)", w)
        self.setting_widgets["dns_bootstrap"] = w
        advanced.addWidget(label('Начальный DNS разрешает имена серверов до подключения и локальные .lan / .local / .home.arpa.', 'caption'))
        w = combo({"proxy": "VPN", "direct": "Напрямую", "block": "Блокировать"})
        form.addRow("Маршрут в «Моих правилах»", w)
        self.setting_widgets["default_action"] = w
        row = QHBoxLayout()
        button("Сохранить и применить", self.save_settings, row, 'primary')
        row.addStretch()
        button("О программе", lambda: QMessageBox.information(self, "Helmsman", f"Helmsman {VERSION}\nGPL-3.0-only, без гарантий. Исходники и лицензии компонентов включены в архив релиза.\nСетевые движки: SagerNet/sing-box, Throne/sing-box, Xray-core, wgcf и ZeroTier Agent (MPL-2.0, без nonfree controller).\nhttps://github.com/ISAIandCO/Helmsman"), row, 'text')
        l.addLayout(row)
        l.addStretch()

    def save_settings(self):
        result = {}
        for key, w in self.setting_widgets.items():
            result[key] = w.isChecked() if isinstance(w, QCheckBox) else w.value() if isinstance(w, (QSpinBox, DNSSelector)) else w.currentData() if isinstance(w, QComboBox) else w.text()
        self.mutate("settings_save", {"settings": result})

    def build_diagnostics(self):
        l = self.page("Диагностика")
        l.addWidget(label('Отчёт исключает ключи и содержимое подписок. Его можно скопировать для обращения с ошибкой.', 'caption'))
        self.diagnostics = area()
        self.diagnostics.setReadOnly(True)
        l.addWidget(self.diagnostics)
        row = QHBoxLayout()
        button("Собрать отчёт", lambda: self.request("diagnostics", callback=lambda r: self.diagnostics.setPlainText(json.dumps(r, ensure_ascii=False, indent=2))), row, 'primary', 'refresh')
        button('Скопировать', lambda: QApplication.clipboard().setText(self.diagnostics.toPlainText()), row)
        row.addStretch(); l.addLayout(row)

    def loaded(self, config):
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
        self.preset_picker.setCurrentIndex(self.preset_picker.findData(config["preset"]))
        self.subscriptions.clear()
        for s in config["subscriptions"]:
            detail = s.get('error') or ('Обновлено ' + datetime.fromtimestamp(s['last_update']).strftime('%d.%m %H:%M') if s.get('last_update') else 'Ещё не обновлялась')
            self.subscriptions.addItem(QListWidgetItem(icon('subscriptions'), s['name'] + '\n' + detail))
        self.subscriptions.setVisible(bool(config['subscriptions']))
        self.subscriptions_empty.setVisible(not config['subscriptions'])
        self.hwid.setText(config["hwid"])
        self.show_rules(config["rules"])
        self.lists.clear()
        for item in config["lists"]:
            when = datetime.fromtimestamp(item["last_update"]).strftime("%d.%m.%Y %H:%M") if item.get("last_update") else "Не загружен"
            self.lists.addItem(QListWidgetItem(icon('lists'), item['name'] + '\n' + (item.get('error') or when)))
        for kind, previous in selected.items():
            view = getattr(self, kind)
            index = next((i for i, item in enumerate(config[kind]) if item['id'] == previous), 0)
            view.setCurrentRow(index if view.count() else -1)
        self.library_summary.setText(f"Подключений: {len(config['profiles'])}")
        self.lan_summary.setText('Локальная сеть доступна напрямую' if config['settings']['lan'] else 'Локальная сеть подчиняется правилам')
        settings = config['settings']
        chosen = next((p for p in config['profiles'] if p['id'] == config['selected']), {})
        self.dns_summary.setText('Через VPN: ' + (chosen.get('dns') or urlsplit(resolver_url(settings['dns_proxy'])).hostname or '') + '\nНапрямую: ' + (urlsplit(resolver_url(settings['dns_direct'])).hostname or ''))
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
            self.statusBar().showMessage("Дождитесь завершения запроса к сервису.")
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
