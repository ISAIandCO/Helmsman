"""Qt Widgets presentation: Material-inspired surfaces, type and vector icons."""
from PySide6.QtCore import QSize, Qt, QRectF, QPointF
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPainterPath, QPalette, QPen, QPixmap
from PySide6.QtWidgets import (QCheckBox, QFrame, QLabel,
                               QStyledItemDelegate, QStyle, QToolButton, QVBoxLayout, QWidget)


COLORS = {"primary": "#cdbdff", "muted": "#aaa7bd", "text": "#f0edf8", "success": "#85dcc4", "error": "#ffb4b0"}


def icon(name, color='#c8c3db', size=24):
    pixmap = QPixmap(size * 2, size * 2)
    pixmap.setDevicePixelRatio(2)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.scale(size / 24, size / 24)
    painter.setPen(QPen(QColor(color), 1.7, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    lines = {
        'home': [[(4,11),(12,4),(20,11)], [(6,10),(6,20),(10,20),(10,14),(14,14),(14,20),(18,20),(18,10)]],
        'profiles': [[(5,5),(19,5),(19,10),(5,10),(5,5)],[(5,14),(19,14),(19,19),(5,19),(5,14)],[(8,7.5),(10,7.5)],[(8,16.5),(10,16.5)]],
        'subscriptions': [[(7,5),(4,5),(4,20),(18,20),(18,5),(15,5)],[(8,3),(14,3),(14,7),(8,7),(8,3)],[(8,11),(14,11)],[(8,15),(13,15)]],
        'rules': [[(5,5),(5,18),(18,18)],[(5,9),(17,9),(17,5)],[(14,6),(17,3),(20,6)],[(15,15),(18,18),(15,21)]],
        'lists': [[(8,6),(20,6)],[(8,12),(20,12)],[(8,18),(20,18)],[(3,6),(4,6)],[(3,12),(4,12)],[(3,18),(4,18)]],
        'settings': [[(4,6),(20,6)],[(4,12),(20,12)],[(4,18),(20,18)]],
        'diagnostics': [[(3,12),(7,12),(10,5),(14,19),(17,12),(21,12)]],
        'plus': [[(12,5),(12,19)],[(5,12),(19,12)]],
        'edit': [[(5,16),(5,20),(9,20),(20,9),(16,5),(5,16)],[(14,7),(18,11)]],
        'delete': [[(5,7),(19,7)],[(9,4),(15,4)],[(7,7),(8,20),(16,20),(17,7)],[(10,10),(10,17)],[(14,10),(14,17)]],
        'refresh': [[(19,4),(19,9),(14,9)],[(5,20),(5,15),(10,15)]],
        'power': [[(12,3),(12,11)]],
        'shield': [[(12,3),(20,6),(19,14),(16,19),(12,22),(8,19),(5,14),(4,6),(12,3)],[(8,12),(11,15),(16,9)]],
        'arrow': [[(5,12),(19,12)],[(14,7),(19,12),(14,17)]],
        'network': [[(12,5),(12,12)],[(5,18),(5,12),(19,12),(19,18)]],
        'warp': [[(8,4),(5,12),(11,12),(9,21),(20,9),(14,9),(16,4),(8,4)]],
    }
    if name == 'info':
        painter.drawEllipse(QRectF(3, 3, 18, 18))
        lines[name] = [[(12, 7), (12, 7.1)], [(12, 11), (12, 17)]]
    if name == 'compass':
        painter.drawEllipse(QRectF(3,3,18,18))
        lines[name] = [[(16,7),(13,14),(7,17),(10,10),(16,7)]]
    if name == 'power':
        painter.drawArc(QRectF(4,4,16,16), 135 * 16, 270 * 16)
    if name == 'refresh':
        painter.drawArc(QRectF(5,5,14,14), 30 * 16, 120 * 16)
        painter.drawArc(QRectF(5,5,14,14), 210 * 16, 120 * 16)
    if name == 'settings':
        for x, y in [(9,6),(16,12),(8,18)]:
            painter.setBrush(QColor('#22212d'))
            painter.drawEllipse(QRectF(x-2.2,y-2.2,4.4,4.4))
    for points in lines.get(name, lines['network']):
        path = QPainterPath(QPointF(*points[0]))
        for point in points[1:]:
            path.lineTo(*point)
        painter.drawPath(path)
    painter.end()
    return QIcon(pixmap)


def label(text='', role='body'):
    widget = QLabel(text)
    widget.setObjectName(role)
    widget.setWordWrap(True)
    return widget


def card(parent_layout=None, role='card'):
    frame = QFrame()
    frame.setObjectName(role)
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(*((18, 10, 18, 10) if role == 'compactCard' else (24, 22, 24, 22)))
    layout.setSpacing(8 if role == 'compactCard' else 12)
    if parent_layout is not None:
        parent_layout.addWidget(frame)
    return frame, layout


def disclosure(title, parent_layout):
    frame, layout = card(parent_layout, 'detailsCard')
    toggle = QToolButton()
    toggle.setText(title)
    toggle.setCheckable(True)
    toggle.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
    toggle.setArrowType(Qt.RightArrow)
    toggle.setObjectName('disclosure')
    pane = QWidget()
    pane.setObjectName('transparent')
    pane_layout = QVBoxLayout(pane)
    pane_layout.setContentsMargins(0, 12, 0, 0)
    pane_layout.setSpacing(12)
    pane.setVisible(False)
    toggle.toggled.connect(lambda opened: (pane.setVisible(opened), toggle.setArrowType(Qt.DownArrow if opened else Qt.RightArrow)))
    layout.addWidget(toggle)
    layout.addWidget(pane)
    return pane_layout


class ListDelegate(QStyledItemDelegate):
    def sizeHint(self, option, index):
        return QSize(240, 82)

    def paint(self, painter, option, index):
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        selected = bool(option.state & QStyle.State_Selected)
        focused = bool(option.state & QStyle.State_HasFocus)
        rect = option.rect.adjusted(3, 4, -3, -4)
        painter.setPen(QPen(QColor('#a99bda' if focused else '#514568' if selected else '#292832'), 1))
        painter.setBrush(QColor('#383044' if selected else '#22212b'))
        painter.drawRoundedRect(QRectF(rect), 18, 18)
        text = index.data(Qt.DisplayRole) or ''
        title, _, detail = text.partition('\n')
        item_icon = index.data(Qt.DecorationRole)
        if isinstance(item_icon, QIcon):
            item_icon.paint(painter, rect.left()+18, rect.top()+24, 24, 24)
        left = rect.left()+58
        width = rect.width()-78
        font = QFont(option.font); font.setPointSizeF(11.5); font.setWeight(QFont.DemiBold)
        painter.setFont(font)
        painter.setPen(QColor('#f0edf8'))
        title = painter.fontMetrics().elidedText(title, Qt.ElideRight, width)
        painter.drawText(left, rect.top()+30, title)
        font.setPointSizeF(9.5); font.setWeight(QFont.Normal)
        painter.setFont(font); painter.setPen(QColor('#b7afc9'))
        detail = painter.fontMetrics().elidedText(detail.replace('\n',' · '), Qt.ElideRight, width)
        painter.drawText(left, rect.top()+53, detail)
        painter.restore()


class Switch(QCheckBox):
    """A native checkbox with a larger touch target and an explicit switch thumb."""
    def sizeHint(self):
        return QSize(self.fontMetrics().horizontalAdvance(self.text()) + 76, 42)

    def hitButton(self, point):
        return self.rect().contains(point)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        y = (self.height() - 26) / 2
        painter.setPen(QPen(QColor('#cdbdff' if self.isChecked() else '#8b819a'), 1.5))
        painter.setBrush(QColor('#cdbdff' if self.isChecked() else '#302936'))
        painter.drawRoundedRect(QRectF(2, y, 46, 26), 13, 13)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor('#342349' if self.isChecked() else '#afa4bd'))
        painter.drawEllipse(QRectF(26 if self.isChecked() else 6, y + 4, 18, 18))
        painter.setPen(QColor(COLORS['text']))
        painter.drawText(self.rect().adjusted(64, 0, 0, 0), Qt.AlignVCenter | Qt.AlignLeft, self.text())
        if self.hasFocus():
            painter.setPen(QPen(QColor(COLORS['primary']), 1))
            painter.setBrush(Qt.NoBrush)
            painter.drawRoundedRect(QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5), 12, 12)
        painter.end()


def theme(app):
    app.setApplicationName('Helmsman')
    app.setStyle('Fusion')
    app.setFont(QFont('Noto Sans', 11))
    palette = QPalette()
    for role, color in ((QPalette.Window, '#14131b'), (QPalette.WindowText, COLORS['text']),
                        (QPalette.Base, '#211f2a'), (QPalette.Text, COLORS['text']),
                        (QPalette.Button, '#332e40'), (QPalette.ButtonText, COLORS['text']),
                        (QPalette.Highlight, COLORS['primary']), (QPalette.HighlightedText, '#271b41')):
        palette.setColor(role, QColor(color))
    app.setPalette(palette)
    app.setStyleSheet('''
QWidget { color: #f0edf8; font-family: "Noto Sans", "DejaVu Sans"; font-size: 14px; }
QMainWindow, QWidget#shell { background: #14131b; }
QWidget#sidebar { background: #1b1923; border-right: 1px solid #2b2836; }
QWidget#transparent, QWidget#page, QStackedWidget, QScrollArea, QScrollArea > QWidget > QWidget { background: transparent; border: none; }
QFrame#card, QFrame#detailsCard, QFrame#compactCard { background: #211f2a; border: none; border-radius: 24px; }
QFrame#compactCard QPushButton { min-height: 34px; border-radius: 17px; }
QFrame#heroCard { background: #292336; border-radius: 30px; }
QFrame#dialog { background: #211f2a; }
QDialog, QMessageBox { background: #211f2a; }
QLabel { background: transparent; border: none; }
QLabel#brand { font-size: 23px; font-weight: 700; letter-spacing: -0.6px; }
QLabel#pageTitle { font-size: 30px; font-weight: 600; letter-spacing: -0.6px; }
QLabel#cardTitle { font-size: 19px; font-weight: 600; }
QLabel#stateTitle { font-size: 38px; font-weight: 600; letter-spacing: -1px; }
QLabel#eyebrow { color: #c1b4dc; font-size: 12px; font-weight: 600; letter-spacing: 1px; }
QLabel#caption { color: #aaa4ba; font-size: 12px; }
QLabel#body { color: #c6c0d2; font-size: 14px; }
QLabel#badge { color: #d5c5f3; background: #352d44; border-radius: 14px; padding: 7px 12px; font-size: 12px; }
QLabel#badge[active="true"] { color: #a0ebd6; background: #243e37; }
QLabel#errorText { color: #ffb4b0; }
QPushButton { background: #332e40; border: 1px solid transparent; border-radius: 21px; min-height: 42px; padding: 0px 17px; font-weight: 500; }
QPushButton:hover { background: #443b55; }
QPushButton:pressed { background: #514460; }
QPushButton:focus { border: 2px solid #cdbdff; }
QPushButton:disabled { color: #787181; background: #292530; }
QPushButton[variant="primary"] { background: #cdbdff; color: #271b41; font-weight: 600; }
QPushButton[variant="primary"]:hover { background: #dfd0ff; }
QPushButton[variant="primary"]:disabled { color: #787181; background: #39313f; }
QPushButton[variant="connect"] { background: #cdbdff; color: #271b41; min-height: 62px; border-radius: 29px; font-size: 18px; font-weight: 600; }
QPushButton[variant="connect"]:disabled { background: #39313f; color: #8c8298; }
QPushButton[variant="danger"] { color: #ffb4b0; background: #402c35; }
QPushButton[variant="text"] { color: #d8c5ff; background: transparent; padding: 0px 10px; }
QPushButton#nav { text-align: left; padding: 0px 16px; border-radius: 18px; background: transparent; font-weight: 500; }
QPushButton#nav:hover { background: #2a2634; }
QPushButton#nav:checked { background: #42354f; color: #ecdfff; }
QPushButton#nav:focus { border: 1px solid #cdbdff; }
QLineEdit, QSpinBox, QComboBox { background: #2b2835; border: 1px solid #61586e; border-radius: 13px; min-height: 42px; padding: 0px 12px; selection-background-color: #74618e; }
QLineEdit:focus, QSpinBox:focus, QComboBox:focus { border: 2px solid #cdbdff; }
QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled { color: #81788c; border-color: #37313f; }
QComboBox { padding-right: 28px; }
QComboBox::drop-down { border: none; width: 28px; }
QComboBox QAbstractItemView { background: #302939; color: #f0edf8; border: 1px solid #62526f; selection-background-color: #51415f; padding: 8px; }
QSpinBox::up-button, QSpinBox::down-button { border: none; width: 22px; }
QPlainTextEdit { background: #1a1821; border: 1px solid #52475f; border-radius: 14px; padding: 12px; selection-background-color: #74618e; }
QPlainTextEdit:focus { border: 2px solid #cdbdff; }
QListWidget { background: transparent; border: none; outline: none; }
QListWidget::item { border-radius: 16px; padding: 12px; min-height: 40px; }
QListWidget::item:selected { background: #42354f; }
QCheckBox { spacing: 12px; min-height: 36px; }
QCheckBox::indicator { width: 22px; height: 22px; border: 2px solid #9d8eae; border-radius: 7px; background: #2b2534; }
QCheckBox::indicator:checked { background: #cdbdff; border-color: #cdbdff; }
QCheckBox::indicator:focus { border-color: #f0edf8; }
QToolButton#disclosure { background: transparent; border: none; color: #d6c9e7; min-height: 32px; font-weight: 600; text-align: left; }
QToolButton#disclosure:focus { border: 1px solid #cdbdff; border-radius: 8px; }
QScrollBar:vertical { width: 8px; margin: 3px; background: transparent; }
QScrollBar::handle:vertical { background: #61566f; border-radius: 3px; min-height: 35px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QStatusBar { background: #14131b; color: #aaa4ba; min-height: 22px; font-size: 11px; }
QStatusBar::item { border: none; }
QToolTip { color: #f0edf8; background: #42354f; border: none; padding: 7px; }
''')
