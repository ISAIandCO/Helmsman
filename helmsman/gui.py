"""Native Qt desktop client. All network operations belong to the service."""
import json
import sys
from pathlib import Path

from PySide6.QtCore import QThread, QTimer, Signal, Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget, QMainWindow, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSpinBox, QTabWidget, QVBoxLayout, QWidget)

from .common import MAX_BYTES, PRESETS, UserError, VERSION
from .rpc import call


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


def button(text, callback, layout):
    b = QPushButton(text)
    b.clicked.connect(callback)
    layout.addWidget(b)
    return b


def combo(items):
    c = QComboBox()
    for key, text in items.items():
        c.addItem(text, key)
    return c


class Form(QDialog):
    def __init__(self, title, fields, parent):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(640, 480)
        self.fields = fields
        layout = QVBoxLayout(self)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        page = QWidget()
        form = QFormLayout(page)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        for key, (name, widget) in fields.items():
            widget.setAccessibleName(name)
            form.addRow(name, widget)
        scroll.setWidget(page)
        layout.addWidget(scroll)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


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


class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Helmsman")
        self.resize(1040, 680)
        self.setMinimumSize(760, 500)
        self.config = None
        self.workers = set()
        self.busy = False
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
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
        content = QWidget()
        layout = QVBoxLayout(content)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(content)
        self.tabs.addTab(scroll, name)
        return layout

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
        l = self.page("Подключение")
        title = QLabel("Helmsman")
        title.setFont(QFont("", 27, QFont.Bold))
        l.addWidget(title)
        self.state_label = QLabel("Ожидание сервиса…")
        self.state_label.setWordWrap(True)
        self.state_label.setFont(QFont("", 15))
        l.addWidget(self.state_label)
        self.profile_picker = QComboBox()
        self.profile_picker.setAccessibleName("Выбранное подключение")
        l.addWidget(QLabel("Подключение"))
        l.addWidget(self.profile_picker)
        button("Выбрать профиль", lambda: self.mutate("select", {"profile_id": self.profile_picker.currentData()}), l)
        self.preset_picker = combo(PRESETS)
        l.addWidget(QLabel("Маршрутизация"))
        l.addWidget(self.preset_picker)
        button("Применить сценарий", lambda: self.mutate("preset", {"preset": self.preset_picker.currentData()}), l)
        row = QHBoxLayout()
        button("Подключить", lambda: self.mutate("connect", {"profile_id": self.profile_picker.currentData()}), row)
        button("Отключить", lambda: self.mutate("disconnect"), row)
        l.addLayout(row)
        button("Проверить доступ через VPN", lambda: self.request("probe", callback=lambda r: QMessageBox.information(self, "Проверка", r["message"])), l)
        hint = QLabel("Соединение продолжает работать после закрытия окна и перехода в Game Mode. Отключение кнопкой снимает защитную блокировку. ZeroTier соединяет устройства в виртуальной сети и не заменяет VPN для интернета.")
        hint.setWordWrap(True)
        l.addWidget(hint)
        l.addStretch()

    def show_status(self, s):
        names = {"disconnected": "Отключено", "running": "VPN включён", "connected": "Подключено", "connecting": "Подключение…", "authorizing": "Ожидание авторизации", "error": "Ошибка подключения"}
        text = names.get(s["state"], s["state"]) + "\n" + s["message"]
        if s.get("guard"):
            text += "\nЗащита от прямого выхода включена."
        if s.get("error"):
            text += "\n" + s["error"]
        if s.get("node_id"):
            text += "\nNode ID: " + s["node_id"]
        if s.get("addresses"):
            text += "\n" + ", ".join(s["addresses"])
        if s.get("last_probe"):
            text += "\nПоследняя проверка: " + s["last_probe"]["message"]
        self.state_label.setText(text)
        if self.profile_picker.currentData() != s["selected"]:
            self.profile_picker.setCurrentIndex(self.profile_picker.findData(s["selected"]))
        self.preset_picker.setCurrentIndex(self.preset_picker.findData(s["preset"]))

    def build_profiles(self):
        l = self.page("Профили")
        self.profiles = QListWidget()
        self.profiles.setAccessibleName("Профили подключений")
        l.addWidget(self.profiles)
        row = QHBoxLayout()
        button("Импорт", self.import_profiles, row)
        button("Изменить", self.edit_profile, row)
        button("Удалить", lambda: self.delete_selected("profile_delete", self.profiles), row)
        l.addLayout(row)
        button("Добавить сеть ZeroTier", self.add_zerotier, l)

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
        text.setPlaceholderText("Вставьте ссылку, список ссылок, sing-box JSON, WireGuard/AmneziaWG .conf, автономный OpenVPN .ovpn или клиентский vpn:// экспорт Amnezia.")
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

    def add_zerotier(self):
        value, ok = QInputDialog.getText(self, "ZeroTier", "Network ID (16 символов):")
        if ok:
            self.mutate("import", {"text": "zerotier://" + value.strip()})

    def build_subscriptions(self):
        l = self.page("Подписки")
        self.subscriptions = QListWidget()
        l.addWidget(self.subscriptions)
        row = QHBoxLayout()
        button("Добавить", lambda: self.edit_subscription(), row)
        button("Изменить", lambda: self.edit_subscription(self.selected_item(self.subscriptions, "subscriptions")), row)
        button("Удалить", lambda: self.delete_selected("subscription_delete", self.subscriptions), row)
        l.addLayout(row)
        button("Обновить все подписки", lambda: self.mutate("subscriptions_update"), l)
        self.hwid = line()
        self.hwid.setAccessibleName("Общий HWID")
        l.addWidget(QLabel("Общий HWID: случайный идентификатор, без серийных номеров устройства"))
        l.addWidget(self.hwid)
        row = QHBoxLayout()
        button("Сохранить HWID", lambda: self.mutate("hwid", {"value": self.hwid.text()}), row)
        button("Сгенерировать новый", lambda: self.mutate("hwid", {"value": ""}), row)
        l.addLayout(row)

    def edit_subscription(self, sub=None):
        sub = sub or {}
        name = line(sub.get("name", "Подписка"))
        url = line(sub.get("url", ""), secret=True)
        interval = integer(sub.get("interval_hours", 24), 0, 720)
        mode = combo({"none": "Не передавать", "remnawave": "Remnawave (x-hwid и описание устройства)", "header": "Указанный HTTP-заголовок", "query": "Указанный параметр URL"})
        mode.setCurrentIndex(mode.findData(sub.get("hwid_mode", "none")))
        hwid_name = line(sub.get("hwid_name", "x-hwid"))
        hwid = line(sub.get("hwid", ""))
        headers = area(json.dumps(sub.get("headers", {}), ensure_ascii=False, indent=2))
        fields = {"name": ("Название", name), "url": ("HTTPS URL", url), "interval": ("Обновление, ч (0 — вручную)", interval), "mode": ("Передача HWID", mode), "hwid_name": ("Имя заголовка / query-параметра", hwid_name), "hwid": ("Свой HWID (пусто — общий)", hwid), "headers": ("Дополнительные HTTP-заголовки (JSON)", headers)}
        d = Form("Подписка", fields, self)
        if d.exec() == QDialog.Accepted:
            try:
                extra = json.loads(headers.toPlainText())
            except ValueError:
                QMessageBox.warning(self, "Подписка", "Заголовки должны быть JSON-объектом.")
                return
            self.mutate("subscription_save", {"id": sub.get("id"), "name": name.text(), "url": url.text(), "interval_hours": interval.value(), "hwid_mode": mode.currentData(), "hwid_name": hwid_name.text(), "hwid": hwid.text(), "headers": extra})

    def build_rules(self):
        l = self.page("Правила")
        info = QLabel("Применяются сверху вниз перед правилами сценария. DNS и доступ к LAN обрабатываются первыми. «VPN» означает выбранный профиль. Правила процессов доступны на Linux, но для Proton/контейнеров надёжнее домены и IP.")
        info.setWordWrap(True)
        l.addWidget(info)
        self.rules = QListWidget()
        self.rules.setDragDropMode(QListWidget.InternalMove)
        self.rules.setAccessibleName("Правила, сверху вниз")
        l.addWidget(self.rules)
        row = QHBoxLayout()
        button("Добавить", lambda: self.edit_rule(), row)
        button("Изменить", lambda: self.edit_rule(self.rules.currentRow()), row)
        button("Удалить", self.remove_rule, row)
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
        for r in rules:
            self.rules.addItem(("✓ " if r["enabled"] else "○ ") + r["name"] + "  ·  " + r["type"] + " → " + r["action"])
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
        self.lists = QListWidget()
        self.lists.setWordWrap(True)
        l.addWidget(self.lists)
        row = QHBoxLayout()
        button("Добавить", self.add_list, row)
        button("Обновить выбранный", self.update_list, row)
        button("Удалить", lambda: self.delete_selected("list_delete", self.lists), row)
        l.addLayout(row)
        button("Скопировать ID", self.copy_list_id, l)
        hint = QLabel("Общественные российские списки — ориентир для маршрутизации, а не точная карта блокировок. До загрузки пресета они не скачиваются. Пользовательские правила сохраняются при смене сценария.")
        hint.setWordWrap(True)
        l.addWidget(hint)

    def add_list(self):
        name, url, content = line("Мой список"), line(), area()
        fmt = combo({"text": "Текст: домен или CIDR на строку", "source": "sing-box source JSON", "srs": "sing-box SRS по HTTPS"})
        d = Form("Добавить список", {"name": ("Название", name), "url": ("HTTPS URL (необязательно)", url), "format": ("Формат", fmt), "content": ("Или содержимое списка", content)}, self)
        if d.exec() == QDialog.Accepted:
            self.mutate("list_save", {"name": name.text(), "url": url.text(), "format": fmt.currentData(), **({"content": content.toPlainText()} if content.toPlainText().strip() else {})})

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
        form = QFormLayout()
        self.setting_widgets = {}
        for key, name in {"kill_switch": "Блокировать прямой выход при сбое VPN", "lan": "Доступ к локальной сети и Remote Play", "ipv6": "Разрешить IPv6 через правила"}.items():
            w = QCheckBox(name)
            form.addRow(w)
            self.setting_widgets[key] = w
        for key, name, low, high in [("mtu", "MTU TUN", 1280, 9000), ("reconnect_seconds", "Повтор подключения, с", 5, 300), ("list_update_hours", "Обновление списков, ч", 1, 720)]:
            w = integer(low, low, high)
            form.addRow(name, w)
            self.setting_widgets[key] = w
        for key, name in [("dns_proxy", "DNS через VPN (DoH, IP)"), ("dns_direct", "Прямой DNS (DoH и начальный UDP, IP)")]:
            w = line()
            form.addRow(name, w)
            self.setting_widgets[key] = w
        w = combo({"proxy": "VPN", "direct": "Напрямую", "block": "Блокировать"})
        form.addRow("Маршрут в «Моих правилах»", w)
        self.setting_widgets["default_action"] = w
        l.addLayout(form)
        button("Сохранить и применить", self.save_settings, l)
        button("О программе и лицензиях", lambda: QMessageBox.information(self, "Helmsman", f"Helmsman {VERSION}\nGPL-3.0-only, без гарантий. Исходники и лицензии компонентов включены в архив релиза.\nСетевые движки: SagerNet/sing-box, Throne/sing-box и ZeroTier Agent (MPL-2.0, без nonfree controller).\nhttps://github.com/ISAIandCO/Helmsman"), l)
        l.addStretch()

    def save_settings(self):
        result = {}
        for key, w in self.setting_widgets.items():
            result[key] = w.isChecked() if isinstance(w, QCheckBox) else w.value() if isinstance(w, QSpinBox) else w.currentData() if isinstance(w, QComboBox) else w.text()
        self.mutate("settings_save", {"settings": result})

    def build_diagnostics(self):
        l = self.page("Диагностика")
        self.diagnostics = area()
        self.diagnostics.setReadOnly(True)
        l.addWidget(self.diagnostics)
        button("Обновить диагностику", lambda: self.request("diagnostics", callback=lambda r: self.diagnostics.setPlainText(json.dumps(r, ensure_ascii=False, indent=2))), l)

    def loaded(self, config):
        self.config = config
        self.profiles.clear()
        self.profile_picker.clear()
        for p in config["profiles"]:
            t = "ZeroTier" if p["kind"] == "zerotier" else "AmneziaWG" if p["outbound"].get("amnezia_wg") else p["outbound"]["type"]
            self.profiles.addItem(p["name"] + " · " + t)
            self.profile_picker.addItem(p["name"] + " · " + t, p["id"])
        self.profile_picker.setCurrentIndex(self.profile_picker.findData(config["selected"]))
        self.preset_picker.setCurrentIndex(self.preset_picker.findData(config["preset"]))
        self.subscriptions.clear()
        for s in config["subscriptions"]:
            self.subscriptions.addItem(s["name"] + (" · " + s["error"] if s.get("error") else ""))
        self.hwid.setText(config["hwid"])
        self.show_rules(config["rules"])
        self.lists.clear()
        import datetime
        for item in config["lists"]:
            when = datetime.datetime.fromtimestamp(item["last_update"]).strftime("%d.%m.%Y %H:%M") if item.get("last_update") else "не загружен"
            self.lists.addItem(item["name"] + " · " + when + "\n" + item["id"] + ("\n" + item["error"] if item.get("error") else ""))
        for key, w in self.setting_widgets.items():
            value = config["settings"][key]
            if isinstance(w, QCheckBox):
                w.setChecked(value)
            elif isinstance(w, QSpinBox):
                w.setValue(int(value))
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


def theme(app):
    app.setApplicationName("Helmsman")
    app.setStyle("Fusion")
    app.setFont(QFont("", 11))
    app.setStyleSheet("QWidget { background: #111d2b; color: #eef4fc; } QPushButton, QComboBox, QLineEdit, QSpinBox { min-height: 36px; padding: 3px 9px; border: 1px solid #42617e; border-radius: 7px; } QPushButton { background: #254d72; } QPushButton:focus, QComboBox:focus { border: 2px solid #64cced; } QPushButton:hover { background: #326a96; } QListWidget, QPlainTextEdit { background: #17283a; border: 1px solid #34506a; padding: 7px; } QTabBar::tab { padding: 12px 9px; } QTabBar::tab:selected { background: #254d72; } QLabel { background: transparent; }")


def main():
    app = QApplication(sys.argv)
    theme(app)
    window = Window()
    window.show()
    app.exec()


if __name__ == "__main__":
    main()
