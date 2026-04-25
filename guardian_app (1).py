"""
Smart File Integrity Guardian
ITBP 301 - Security Principles & Practice
UAEU - Spring 2026
Group 7: Mustafa Al Juboori, Tahnoon Almazrouei, Abdulaziz Mura, Ali Alghaithi
"""

import sys
import os
import hashlib
import json
import time
import threading
import random
from datetime import datetime
from pathlib import Path
from collections import deque

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QTableWidget, QTableWidgetItem,
    QTextEdit, QSplitter, QFrame, QHeaderView, QProgressBar,
    QMessageBox, QTabWidget, QGroupBox, QGridLayout, QStatusBar
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject, QThread
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon

import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, f1_score


# ─────────────────────────────────────────────────────
#  AI MODULE
# ─────────────────────────────────────────────────────

def generate_training_data(n_normal=500, n_suspicious=200):
    """
    Generate labelled synthetic feature data for training.
    Features: [mod_freq_per_min, files_in_burst, pct_sensitive, hour_of_day, rapid_rename]
    Label: 0 = normal, 1 = suspicious
    """
    rng = np.random.default_rng(42)

    # Normal behaviour
    normal = np.column_stack([
        rng.uniform(0, 5, n_normal),          # low mod frequency
        rng.integers(1, 4, n_normal),          # small burst size
        rng.uniform(0, 0.3, n_normal),         # few sensitive files
        rng.integers(8, 20, n_normal),         # business hours
        rng.choice([0, 1], n_normal, p=[0.9, 0.1]),  # rare renames
    ])

    # Suspicious (ransomware-like)
    suspicious = np.column_stack([
        rng.uniform(20, 100, n_suspicious),    # high frequency
        rng.integers(10, 50, n_suspicious),    # large burst
        rng.uniform(0.5, 1.0, n_suspicious),   # many sensitive files
        rng.integers(0, 8, n_suspicious // 2).tolist() +
        rng.integers(22, 24, n_suspicious - n_suspicious // 2).tolist(),  # off-hours
        rng.choice([0, 1], n_suspicious, p=[0.1, 0.9]),  # frequent renames
    ])

    X = np.vstack([normal, suspicious])
    y = np.array([0] * n_normal + [1] * n_suspicious)
    return X, y


class AnomalyDetector:
    """Trains Decision Tree + Logistic Regression; uses DT for live inference."""

    def __init__(self):
        self.scaler = StandardScaler()
        self.dt = DecisionTreeClassifier(max_depth=5, random_state=42)
        self.lr = LogisticRegression(max_iter=1000, random_state=42)
        self.trained = False
        self.dt_accuracy = 0.0
        self.lr_accuracy = 0.0
        self.dt_f1 = 0.0
        self.lr_f1 = 0.0

    def train(self):
        X, y = generate_training_data()
        # 80/20 split (manual, no sklearn import needed)
        split = int(0.8 * len(X))
        idx = np.random.default_rng(0).permutation(len(X))
        X_train, X_test = X[idx[:split]], X[idx[split:]]
        y_train, y_test = y[idx[:split]], y[idx[split:]]

        X_train_s = self.scaler.fit_transform(X_train)
        X_test_s  = self.scaler.transform(X_test)

        self.dt.fit(X_train_s, y_train)
        self.lr.fit(X_train_s, y_train)

        dt_pred = self.dt.predict(X_test_s)
        lr_pred = self.lr.predict(X_test_s)

        self.dt_accuracy = accuracy_score(y_test, dt_pred)
        self.lr_accuracy = accuracy_score(y_test, lr_pred)
        self.dt_f1 = f1_score(y_test, dt_pred)
        self.lr_f1 = f1_score(y_test, lr_pred)
        self.trained = True

    def predict(self, features: list) -> tuple[int, float]:
        """Return (label, confidence). label: 0=normal, 1=suspicious."""
        if not self.trained:
            return 0, 0.0
        arr = self.scaler.transform([features])
        label = int(self.dt.predict(arr)[0])
        proba = float(self.dt.predict_proba(arr)[0][label])
        return label, proba


# ─────────────────────────────────────────────────────
#  FILE MONITOR WORKER
# ─────────────────────────────────────────────────────

class MonitorSignals(QObject):
    event       = pyqtSignal(dict)   # file event
    alert       = pyqtSignal(dict)   # AI alert
    status      = pyqtSignal(str)
    stats       = pyqtSignal(dict)


class FileMonitorWorker(QThread):
    def __init__(self, watch_path: str, detector: AnomalyDetector):
        super().__init__()
        self.watch_path  = watch_path
        self.detector    = detector
        self.signals     = MonitorSignals()
        self._running    = False
        self.baseline    = {}          # path -> sha256
        self.event_log   = deque(maxlen=200)
        self.mod_times   = deque(maxlen=100)  # timestamps of recent mods
        self.total_alerts = 0
        self.total_changes = 0

    def run(self):
        self._running = True
        self.signals.status.emit("Building baseline…")
        self._build_baseline()
        self.signals.status.emit(f"Monitoring {self.watch_path}")

        while self._running:
            self._scan()
            time.sleep(2)

    def stop(self):
        self._running = False

    def _hash_file(self, path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError):
            return ""

    def _build_baseline(self):
        self.baseline = {}
        for p in Path(self.watch_path).rglob("*"):
            if p.is_file():
                self.baseline[str(p)] = self._hash_file(str(p))

    def _scan(self):
        current_files = {}
        for p in Path(self.watch_path).rglob("*"):
            if p.is_file():
                current_files[str(p)] = None  # lazy hash

        burst_count = 0

        for path in list(current_files.keys()):
            h = self._hash_file(path)
            current_files[path] = h

            if path not in self.baseline:
                self._emit_event(path, "CREATED", h)
                burst_count += 1
            elif h != self.baseline[path] and h:
                self._emit_event(path, "MODIFIED", h)
                burst_count += 1

            self.baseline[path] = h

        for path in list(self.baseline.keys()):
            if path not in current_files:
                self._emit_event(path, "DELETED", "")
                del self.baseline[path]
                burst_count += 1

        if burst_count > 0:
            self.total_changes += burst_count
            self.mod_times.append(time.time())
            self._check_anomaly(burst_count)

        self.signals.stats.emit({
            "monitored": len(self.baseline),
            "changes":   self.total_changes,
            "alerts":    self.total_alerts,
        })

    def _emit_event(self, path: str, event_type: str, digest: str):
        entry = {
            "time":      datetime.now().strftime("%H:%M:%S"),
            "type":      event_type,
            "path":      os.path.basename(path),
            "full_path": path,
            "hash":      digest[:16] + "…" if digest else "N/A",
        }
        self.event_log.appendleft(entry)
        self.signals.event.emit(entry)

    def _check_anomaly(self, burst_count: int):
        now = time.time()
        recent = [t for t in self.mod_times if now - t < 60]
        freq_per_min = len(recent)
        hour_of_day  = datetime.now().hour
        sensitive    = self._sensitive_ratio()
        rapid_rename = 1 if burst_count > 5 else 0

        features = [freq_per_min, burst_count, sensitive, hour_of_day, rapid_rename]
        label, conf = self.detector.predict(features)

        if label == 1:
            self.total_alerts += 1
            self.signals.alert.emit({
                "time":       datetime.now().strftime("%H:%M:%S"),
                "confidence": f"{conf:.0%}",
                "freq":       freq_per_min,
                "burst":      burst_count,
                "sensitive":  f"{sensitive:.0%}",
            })

    def _sensitive_ratio(self) -> float:
        sensitive_exts = {".docx", ".xlsx", ".pdf", ".db", ".sql", ".key", ".pem"}
        if not self.baseline:
            return 0.0
        count = sum(1 for p in self.baseline if Path(p).suffix.lower() in sensitive_exts)
        return count / len(self.baseline)


# ─────────────────────────────────────────────────────
#  DEMO TAMPERING SIMULATOR
# ─────────────────────────────────────────────────────

class TamperSimulator(QThread):
    """Writes random changes to watched folder for demo purposes."""
    def __init__(self, path: str):
        super().__init__()
        self.path = path
        self._active = False

    def run(self):
        self._active = True
        files = list(Path(self.path).glob("*.txt"))
        i = 0
        while self._active and i < 20:
            if files:
                target = random.choice(files)
                try:
                    with open(target, "a") as f:
                        f.write(f"\nModified at {datetime.now()}")
                except:
                    pass
            time.sleep(0.4)
            i += 1

    def stop(self):
        self._active = False


# ─────────────────────────────────────────────────────
#  MAIN WINDOW
# ─────────────────────────────────────────────────────

DARK_BG   = "#1E1E2E"
CARD_BG   = "#2A2A3E"
ACCENT    = "#7C6AF7"
ACCENT2   = "#5BC0EB"
DANGER    = "#FF6B6B"
SUCCESS   = "#5CDB95"
TEXT_MAIN = "#E0E0F0"
TEXT_SUB  = "#8888AA"
BORDER    = "#3A3A5A"


def qcolor(hex_str):
    return QColor(hex_str)


class MainWindow(QMainWindow):
    def __init__(self, detector: AnomalyDetector):
        super().__init__()
        self.detector = detector
        self.worker   = None
        self.sim      = None
        self.watch_path = None

        self.setWindowTitle("Smart File Integrity Guardian  |  ITBP 301 – Group 7")
        self.setMinimumSize(1100, 720)
        self._apply_stylesheet()
        self._build_ui()

    # ── Stylesheet ──────────────────────────────────────
    def _apply_stylesheet(self):
        self.setStyleSheet(f"""
        QMainWindow, QWidget {{ background: {DARK_BG}; color: {TEXT_MAIN}; font-family: 'Segoe UI', Arial; font-size: 13px; }}
        QTabWidget::pane   {{ border: 1px solid {BORDER}; background: {CARD_BG}; border-radius: 6px; }}
        QTabBar::tab       {{ background: {CARD_BG}; color: {TEXT_SUB}; padding: 8px 20px; border-radius: 4px; margin: 2px; }}
        QTabBar::tab:selected {{ background: {ACCENT}; color: white; font-weight: bold; }}
        QPushButton        {{ background: {ACCENT}; color: white; border: none; padding: 8px 18px; border-radius: 6px; font-weight: bold; }}
        QPushButton:hover  {{ background: #9080FF; }}
        QPushButton:disabled {{ background: #444466; color: {TEXT_SUB}; }}
        QPushButton#danger  {{ background: {DANGER}; }}
        QPushButton#danger:hover {{ background: #FF8888; }}
        QPushButton#neutral {{ background: #3A3A5A; }}
        QPushButton#neutral:hover {{ background: #4A4A6A; }}
        QTableWidget       {{ background: {CARD_BG}; border: 1px solid {BORDER}; gridline-color: {BORDER}; border-radius: 4px; }}
        QHeaderView::section {{ background: #333355; color: {TEXT_MAIN}; padding: 6px; border: none; font-weight: bold; }}
        QTableWidget::item {{ padding: 4px 8px; }}
        QTextEdit          {{ background: {CARD_BG}; border: 1px solid {BORDER}; border-radius: 4px; color: {TEXT_MAIN}; }}
        QGroupBox          {{ border: 1px solid {BORDER}; border-radius: 6px; margin-top: 10px; padding-top: 12px; font-weight: bold; color: {ACCENT2}; }}
        QStatusBar         {{ background: {CARD_BG}; color: {TEXT_SUB}; border-top: 1px solid {BORDER}; }}
        QLabel#title       {{ font-size: 18px; font-weight: bold; color: {ACCENT}; }}
        QLabel#subtitle    {{ font-size: 11px; color: {TEXT_SUB}; }}
        QLabel#stat        {{ font-size: 28px; font-weight: bold; color: {ACCENT2}; }}
        QLabel#stat_label  {{ font-size: 11px; color: {TEXT_SUB}; }}
        QLabel#alert_label {{ color: {DANGER}; font-weight: bold; font-size: 14px; }}
        """)

    # ── Build UI ────────────────────────────────────────
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setSpacing(10)
        root.setContentsMargins(16, 12, 16, 8)

        # Header
        root.addLayout(self._build_header())

        # Stats row
        root.addWidget(self._build_stats_row())

        # Tabs
        tabs = QTabWidget()
        tabs.addTab(self._build_monitor_tab(), "📁  File Monitor")
        tabs.addTab(self._build_alerts_tab(),  "⚠️   AI Alerts")
        tabs.addTab(self._build_ai_tab(),      "🤖  AI Performance")
        root.addWidget(tabs, 1)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready — select a folder to begin monitoring.")

    def _build_header(self):
        row = QHBoxLayout()
        left = QVBoxLayout()
        title = QLabel("Smart File Integrity Guardian")
        title.setObjectName("title")
        sub   = QLabel("SHA-256 Hashing  ·  AI Anomaly Detection  ·  ITBP 301 – Group 7  ·  UAEU Spring 2026")
        sub.setObjectName("subtitle")
        left.addWidget(title)
        left.addWidget(sub)
        row.addLayout(left, 1)

        self.btn_select  = QPushButton("📂  Select Folder")
        self.btn_select.setFixedWidth(160)
        self.btn_start   = QPushButton("▶  Start Monitor")
        self.btn_start.setFixedWidth(160)
        self.btn_start.setEnabled(False)
        self.btn_stop    = QPushButton("⏹  Stop")
        self.btn_stop.setObjectName("danger")
        self.btn_stop.setFixedWidth(120)
        self.btn_stop.setEnabled(False)
        self.btn_sim     = QPushButton("🔥  Simulate Attack")
        self.btn_sim.setObjectName("neutral")
        self.btn_sim.setFixedWidth(160)
        self.btn_sim.setEnabled(False)

        self.btn_select.clicked.connect(self._select_folder)
        self.btn_start.clicked.connect(self._start_monitoring)
        self.btn_stop.clicked.connect(self._stop_monitoring)
        self.btn_sim.clicked.connect(self._simulate_attack)

        for b in [self.btn_select, self.btn_start, self.btn_stop, self.btn_sim]:
            row.addWidget(b)

        return row

    def _build_stats_row(self):
        frame = QFrame()
        frame.setStyleSheet(f"background:{CARD_BG}; border:1px solid {BORDER}; border-radius:8px;")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(20, 12, 20, 12)

        stats = [
            ("monitored_val",  "0", "Files Monitored"),
            ("changes_val",    "0", "Changes Detected"),
            ("alerts_val",     "0", "AI Alerts Fired"),
            ("model_val",      "—", "DT Accuracy"),
            ("path_val",       "None", "Watch Path"),
        ]
        self.stat_labels = {}
        for attr, init, label in stats:
            col = QVBoxLayout()
            col.setAlignment(Qt.AlignCenter)
            val = QLabel(init)
            val.setObjectName("stat")
            val.setAlignment(Qt.AlignCenter)
            lbl = QLabel(label)
            lbl.setObjectName("stat_label")
            lbl.setAlignment(Qt.AlignCenter)
            col.addWidget(val)
            col.addWidget(lbl)
            self.stat_labels[attr] = val
            layout.addLayout(col)
            if label != "Watch Path":
                sep = QFrame()
                sep.setFrameShape(QFrame.VLine)
                sep.setStyleSheet(f"color:{BORDER};")
                layout.addWidget(sep)

        return frame

    def _build_monitor_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(8, 8, 8, 8)

        self.event_table = QTableWidget(0, 5)
        self.event_table.setHorizontalHeaderLabels(["Time", "Event", "File", "SHA-256 (prefix)", "Full Path"])
        self.event_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.event_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.event_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.event_table.setAlternatingRowColors(True)
        self.event_table.setStyleSheet(f"alternate-background-color: #252538;")

        layout.addWidget(QLabel("  Live File Events"), 0)
        layout.addWidget(self.event_table, 1)
        return w

    def _build_alerts_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(8, 8, 8, 8)

        self.alert_table = QTableWidget(0, 5)
        self.alert_table.setHorizontalHeaderLabels(["Time", "Confidence", "Mod Freq/min", "Burst Size", "Sensitive File %"])
        self.alert_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.alert_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.alert_table.setEditTriggers(QTableWidget.NoEditTriggers)

        self.alert_banner = QLabel("  No active alerts.")
        self.alert_banner.setObjectName("alert_label")
        self.alert_banner.setStyleSheet(f"background:{CARD_BG}; padding:8px; border-radius:4px;")

        layout.addWidget(self.alert_banner)
        layout.addWidget(self.alert_table, 1)
        return w

    def _build_ai_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # Model metrics
        grp = QGroupBox("Model Performance Metrics (Held-Out Test Set)")
        grid = QGridLayout(grp)
        grid.setSpacing(12)

        metrics = [
            ("Decision Tree Accuracy",    "dt_acc"),
            ("Decision Tree F1-Score",    "dt_f1"),
            ("Logistic Regression Acc.",  "lr_acc"),
            ("Logistic Regression F1",    "lr_f1"),
        ]
        self.metric_labels = {}
        for i, (name, key) in enumerate(metrics):
            row, col = divmod(i, 2)
            card = QFrame()
            card.setStyleSheet(f"background:#1A1A2E; border-radius:8px; padding:8px;")
            cl = QVBoxLayout(card)
            val = QLabel("—")
            val.setObjectName("stat")
            val.setAlignment(Qt.AlignCenter)
            lbl = QLabel(name)
            lbl.setObjectName("stat_label")
            lbl.setAlignment(Qt.AlignCenter)
            cl.addWidget(val)
            cl.addWidget(lbl)
            grid.addWidget(card, row, col)
            self.metric_labels[key] = val
        layout.addWidget(grp)

        # Feature description
        grp2 = QGroupBox("Feature Vector Description")
        fl = QVBoxLayout(grp2)
        features_text = QTextEdit()
        features_text.setReadOnly(True)
        features_text.setMaximumHeight(180)
        features_text.setPlainText(
            "Feature 1 — Modification frequency (modifications/min): captures high-rate file churn typical of ransomware.\n"
            "Feature 2 — Burst size (files modified in one scan cycle): large bursts indicate mass-encryption events.\n"
            "Feature 3 — Sensitive file ratio (%.docx/.pdf/.db/.key): attackers target high-value data files first.\n"
            "Feature 4 — Hour of day (0–23): off-hours activity (midnight attacks) is a strong anomaly indicator.\n"
            "Feature 5 — Rapid rename flag (binary): ransomware frequently renames files with encrypted extensions.\n\n"
            "Training data: 500 normal + 200 suspicious synthetic events. Models compared: Decision Tree (depth=5) vs Logistic Regression."
        )
        fl.addWidget(features_text)
        layout.addWidget(grp2)
        layout.addStretch()

        # Populate metrics if already trained
        self._refresh_metrics()
        return w

    # ── Slots ────────────────────────────────────────────
    def _select_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select folder to monitor")
        if path:
            self.watch_path = path
            self.btn_start.setEnabled(True)
            self.stat_labels["path_val"].setText(os.path.basename(path) or path)
            self.status_bar.showMessage(f"Selected: {path}")

    def _start_monitoring(self):
        if not self.watch_path:
            return
        self.worker = FileMonitorWorker(self.watch_path, self.detector)
        self.worker.signals.event.connect(self._on_event)
        self.worker.signals.alert.connect(self._on_alert)
        self.worker.signals.status.connect(self.status_bar.showMessage)
        self.worker.signals.stats.connect(self._on_stats)
        self.worker.start()

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_sim.setEnabled(True)
        self.btn_select.setEnabled(False)

    def _stop_monitoring(self):
        if self.worker:
            self.worker.stop()
            self.worker = None
        if self.sim:
            self.sim.stop()
            self.sim = None
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_sim.setEnabled(False)
        self.btn_select.setEnabled(True)
        self.status_bar.showMessage("Monitoring stopped.")

    def _simulate_attack(self):
        """Create sample files then rapidly modify them to trigger AI alert."""
        # Create dummy files first
        for i in range(10):
            fpath = os.path.join(self.watch_path, f"document_{i:02d}.docx")
            if not os.path.exists(fpath):
                with open(fpath, "w") as f:
                    f.write(f"Sample document {i}\nContains sensitive data.")

        self.sim = TamperSimulator(self.watch_path)
        self.sim.start()
        self.status_bar.showMessage("⚠ Attack simulation running — modifying files rapidly…")

    def _on_event(self, entry: dict):
        row = self.event_table.rowCount()
        self.event_table.insertRow(row)
        cols = [entry["time"], entry["type"], entry["path"], entry["hash"], entry["full_path"]]
        for c, val in enumerate(cols):
            item = QTableWidgetItem(val)
            if entry["type"] == "MODIFIED":
                item.setForeground(qcolor("#F9C74F"))
            elif entry["type"] == "CREATED":
                item.setForeground(qcolor(SUCCESS))
            elif entry["type"] == "DELETED":
                item.setForeground(qcolor(DANGER))
            self.event_table.setItem(row, c, item)
        self.event_table.scrollToBottom()

    def _on_alert(self, alert: dict):
        row = self.alert_table.rowCount()
        self.alert_table.insertRow(row)
        cols = [alert["time"], alert["confidence"], str(alert["freq"]), str(alert["burst"]), alert["sensitive"]]
        for c, val in enumerate(cols):
            item = QTableWidgetItem(val)
            item.setForeground(qcolor(DANGER))
            item.setFont(QFont("Segoe UI", 12, QFont.Bold))
            self.alert_table.setItem(row, c, item)
        self.alert_table.scrollToBottom()
        self.alert_banner.setText(
            f"  🚨 ALERT — Suspicious activity detected at {alert['time']}  |  "
            f"Confidence: {alert['confidence']}  |  Burst: {alert['burst']} files"
        )
        self.stat_labels["alerts_val"].setStyleSheet(f"color:{DANGER}; font-size:28px; font-weight:bold;")

    def _on_stats(self, stats: dict):
        self.stat_labels["monitored_val"].setText(str(stats["monitored"]))
        self.stat_labels["changes_val"].setText(str(stats["changes"]))
        self.stat_labels["alerts_val"].setText(str(stats["alerts"]))

    def _refresh_metrics(self):
        if self.detector.trained:
            self.metric_labels["dt_acc"].setText(f"{self.detector.dt_accuracy:.1%}")
            self.metric_labels["dt_f1"].setText(f"{self.detector.dt_f1:.1%}")
            self.metric_labels["lr_acc"].setText(f"{self.detector.lr_accuracy:.1%}")
            self.metric_labels["lr_f1"].setText(f"{self.detector.lr_f1:.1%}")
            self.stat_labels["model_val"].setText(f"{self.detector.dt_accuracy:.1%}")


# ─────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Smart File Integrity Guardian")

    # Train AI on startup (fast — synthetic data)
    detector = AnomalyDetector()
    detector.train()

    window = MainWindow(detector)
    window._refresh_metrics()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
