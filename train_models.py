"""
train_models.py — PhishGuard AI
XGBoost = Primary model | 8 models total
Handles class imbalance via scale_pos_weight + SMOTE + class_weight
"""
import pandas as pd, numpy as np, pickle, os, json, warnings
warnings.filterwarnings("ignore")

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, recall_score, precision_score
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier

from feature_extraction import extract_features

BASE       = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE, "models")
os.makedirs(MODELS_DIR, exist_ok=True)

# ── Load dataset ──────────────────────────────────────────────────────────────
print("📂 Loading dataset...")
df = pd.read_csv(os.path.join(BASE, "dataset.csv"))
df = df.dropna(subset=["url", "label"])
df["label"] = df["label"].astype(int)

ph = df["label"].sum()
sf = (df["label"] == 0).sum()
print(f"   Phishing: {ph:,} | Safe: {sf:,} | Ratio: {max(ph,sf)/min(ph,sf):.1f}x")

# ── Extract features ──────────────────────────────────────────────────────────
print("\n⚙️  Extracting features...")
feats_list, valid_idx = [], []

for i, row in enumerate(df.itertuples()):
    try:
        feats_list.append(extract_features(str(row.url)))
        valid_idx.append(i)
    except:
        pass
    if (i + 1) % 5000 == 0:
        print(f"   {i+1}/{len(df)}...")

df = df.iloc[valid_idx].reset_index(drop=True)
X  = pd.DataFrame(feats_list)
y  = df["label"].values
FEATURE_NAMES = list(X.columns)

print(f"✅ {X.shape[1]} features from {X.shape[0]} URLs")

# ── Train/test split ──────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ── Imbalance: compute ratio BEFORE SMOTE ─────────────────────────────────────
scale_pos = (y_train == 0).sum() / max((y_train == 1).sum(), 1)

# ── SMOTE ─────────────────────────────────────────────────────────────────────
try:
    from imblearn.over_sampling import SMOTE
    X_train, y_train = SMOTE(random_state=42).fit_resample(X_train, y_train)
    print(f"✅ SMOTE applied → {len(X_train):,} samples")
except ImportError:
    print("⚠  SMOTE not installed — using class_weight (pip install imbalanced-learn)")

# ── Scaling ───────────────────────────────────────────────────────────────────
scaler   = StandardScaler()
X_tr_sc  = scaler.fit_transform(X_train)
X_te_sc  = scaler.transform(X_test)
SCALED   = {"mlp", "logistic_regression", "knn"}

with open(f"{MODELS_DIR}/scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)

with open(f"{MODELS_DIR}/feature_names.pkl", "wb") as f:
    pickle.dump(FEATURE_NAMES, f)

print(f"✅ Scaler and {len(FEATURE_NAMES)} feature names saved")

# ── Define 8 models (XGBoost = PRIMARY) ───────────────────────────────────────
DISPLAY = {
    "xgboost":            "XGBoost",
    "gradient_boosting":  "Gradient Boosting",
    "random_forest":      "Random Forest",
    "decision_tree":      "Decision Tree",
    "mlp":                "MLP Classifier",
    "logistic_regression":"Logistic Regression",
    "knn":                "K-Nearest Neighbors",
    "naive_bayes":        "Naive Bayes",
}

models = {
    "xgboost": XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.08,
        subsample=0.85, colsample_bytree=0.85, min_child_weight=3,
        scale_pos_weight=scale_pos,
        random_state=42, eval_metric="logloss",
        verbosity=0, use_label_encoder=False,
    ),
    "gradient_boosting": GradientBoostingClassifier(
        n_estimators=200, max_depth=5, learning_rate=0.1,
        subsample=0.85, random_state=42
    ),
    "random_forest": RandomForestClassifier(
        n_estimators=200, max_depth=10,
        class_weight="balanced", random_state=42, n_jobs=-1
    ),
    "decision_tree": DecisionTreeClassifier(
        max_depth=10, class_weight="balanced", random_state=42
    ),
    "mlp": MLPClassifier(
        hidden_layer_sizes=(128, 64, 32), activation="relu",
        max_iter=400, early_stopping=True, random_state=42
    ),
    "logistic_regression": LogisticRegression(
        max_iter=1000, C=1.0, class_weight="balanced", random_state=42
    ),
    "knn": KNeighborsClassifier(
        n_neighbors=7, weights="distance", n_jobs=-1
    ),
    "naive_bayes": GaussianNB(),
}

# ── Train & evaluate ──────────────────────────────────────────────────────────
print("\n🚀 Training 8 models (XGBoost = PRIMARY)...\n")
results_acc  = {}
feat_imp_data = {}
best_model   = None
best_acc     = 0.0

for name, model in models.items():
    print(f"  {name}...", end="  ", flush=True)
    try:
        Xtr = X_tr_sc if name in SCALED else X_train
        Xte = X_te_sc if name in SCALED else X_test

        model.fit(Xtr, y_train)
        yp   = model.predict(Xte)
        acc  = accuracy_score(y_test, yp)
        f1   = f1_score(y_test, yp, average="weighted")
        rec  = recall_score(y_test, yp, average="weighted")
        prec = precision_score(y_test, yp, average="weighted")

        results_acc[DISPLAY[name]] = round(acc * 100, 2)
        print(f"Acc={acc:.4%}  F1={f1:.4%}  Recall={rec:.4%}  Precision={prec:.4%}")

        with open(f"{MODELS_DIR}/{name}.pkl", "wb") as f:
            pickle.dump(model, f)

        if acc > best_acc:
            best_acc   = acc
            best_model = name

    except Exception as e:
        print(f"❌ {e}")

# ── Feature importances from XGBoost ─────────────────────────────────────────
xgb = models.get("xgboost")
if xgb and hasattr(xgb, "feature_importances_"):
    fi = {
        n: round(float(v), 6)
        for n, v in sorted(
            zip(FEATURE_NAMES, xgb.feature_importances_),
            key=lambda x: x[1], reverse=True
        )
    }
    with open(f"{MODELS_DIR}/feature_importances.json", "w") as f:
        json.dump(fi, f, indent=2)
    print(f"\n   Top 5 features: {list(fi.keys())[:5]}")

# ── Save results ──────────────────────────────────────────────────────────────
with open(f"{MODELS_DIR}/results.json", "w") as f:
    json.dump(results_acc, f, indent=2)

with open(f"{MODELS_DIR}/best_model.txt", "w") as f:
    f.write(best_model or "xgboost")

# ── Summary ───────────────────────────────────────────────────────────────────
print("\n" + "=" * 58)
print(f"  {best_model}  ({best_acc:.4%})")
print("\n📈 Model Ranking (Accuracy):")
for n, a in sorted(results_acc.items(), key=lambda x: x[1], reverse=True):
    bar = "█" * int(a / 5)
    print(f"   {n:<24} {bar:<20} {a}%")
print("=" * 58)
print(f"\n✅ All models saved to: {MODELS_DIR}")
print("   Run:  python app.py\n")
