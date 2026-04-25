# Smart File Integrity Guardian
**ITBP 301 – Security Principles & Practice | UAEU Spring 2026 | Group 7**

## Overview
A Python desktop application that combines SHA-256 cryptographic hashing with AI-based anomaly detection to monitor folders for unauthorized file modifications in real time.

## Features
- Real-time SHA-256 hash-based file integrity monitoring
- Decision Tree + Logistic Regression anomaly detection
- Ransomware-like attack simulation for demo
- PyQt5 dark-themed GUI with live event feed and AI alert panel

## Installation

```bash
pip install -r requirements.txt
```

> **Note:** PyQt5 requires Python 3.8–3.11. On newer Python, try `pip install PyQt5 --config-settings --confirm-license=`.

## Usage

```bash
python guardian_app.py
```

1. Click **Select Folder** to choose a directory to monitor
2. Click **Start Monitor** to begin watching
3. Click **Simulate Attack** to trigger a ransomware-like burst (creates + modifies files)
4. View live events on the **File Monitor** tab and AI alerts on the **AI Alerts** tab
5. Check model accuracy on the **AI Performance** tab

## AI Architecture
- **Training data:** 700 synthetic labelled events (500 normal + 200 suspicious)
- **Features:** mod frequency, burst size, sensitive file ratio, hour of day, rapid rename flag
- **Models:** Decision Tree (depth=5) and Logistic Regression, evaluated on 20% held-out test set

## Team
- Mustafa Al Juboori
- Tahnoon Almazrouei
- Abdulaziz Mura
- Ali Alghaithi
