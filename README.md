# PhishGuard AI — Desktop Application
## Final Year Project | URL Phishing Detection using Machine Learning

---

## 🚀 Quick Start

### Step 1 — Install Dependencies
```bash
pip install PyQt5 flask pandas numpy scikit-learn xgboost
```

### Step 2 — Train Models (one time only)
```bash
python train_models.py
```
⏱ Takes ~5 minutes for 50,000 URLs

### Step 3 — Launch Desktop App
```bash
python phishguard_app.py
```
Or double-click **RUN_APP.bat** on Windows

---

## 📁 Project Files

| File | Purpose |
|------|---------|
| `phishguard_app.py` | **Main desktop app** (PyQt5) |
| `train_models.py` | Train all 8 ML models |
| `feature_extraction.py` | Extract 30 features from URLs |
| `blacklist.py` | SQLite blacklist database |
| `whitelist.py` | Trusted domain whitelist |
| `app.py` | Flask web version (optional) |
| `dataset.csv` | Training data (50K URLs) |
| `RUN_APP.bat` | Windows launcher |

---

## 🛡 Features

### Desktop App Pages
- **Scanner** — URL scan with SSL check + severity score
- **Analytics** — Model accuracy charts + feature importance
- **History** — Complete audit log of all scans
- **Blacklist** — Auto-growing threat database

### Cybersecurity Features
- ✅ SSL Certificate Checker
- ✅ Live Threat Feed Ticker
- ✅ Threat Severity Score (SAFE/LOW/MEDIUM/HIGH/CRITICAL)
- ✅ Auto-blacklist with SQLite
- ✅ 3-Layer Defense (Whitelist → ML → Auto-Learn)
- ✅ Real-time security tips in sidebar

### ML Models (8 total)
1. XGBoost ⭐ Primary
2. Gradient Boosting
3. Random Forest
4. Decision Tree
5. MLP Classifier
6. Logistic Regression
7. K-Nearest Neighbors
8. Naive Bayes

---

## 🔧 Tech Stack
- **Language:** Python 3.10+
- **Desktop UI:** PyQt5
- **ML:** XGBoost, Scikit-learn
- **Database:** SQLite3
- **Web (optional):** Flask
