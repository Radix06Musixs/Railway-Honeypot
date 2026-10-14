"""Stage 4/5 - Feature engineering + ML-based evaluation.

Per-session behavioural features are scored by a classifier trained at start-up on a synthetic
corpus of benign banking customers and several attacker personas (scanner, brute-forcer, SQL
injector, low-and-slow, adaptive/agentic).  Four model families are trained and compared with
Accuracy / Precision / Recall / F1 / ROC-AUC, as in the flowchart.  The best by F1 drives live scoring.
Replace `generate_dataset()` with your own labelled honeypot logs for real research results.
"""
import time
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

try:  # optional
    from xgboost import XGBClassifier
except Exception:  # pragma: no cover
    XGBClassifier = None

FEATURES = [
    "req_count", "req_rate", "unique_paths", "ratio_404", "sensitive_ratio", "scanner_ua",
    "login_fails", "method_div", "sqli_hits", "traversal_hits", "mean_gap", "ua_changes",
    "decoy_hits", "port_hits",
]


def _persona(rng, kind):
    u = rng.uniform
    ri = lambda a, b: int(rng.integers(a, b + 1))
    if kind == "benign":
        n = ri(2, 60)
        return [n, u(1, 25), min(n, ri(1, 12)), u(0, .12), u(0, .02) if rng.random() < .03 else 0, 0,
                ri(0, 3), ri(1, 2), 1 if rng.random() < .01 else 0, 0, u(2, 40), 0,
                1 if rng.random() < .01 else 0, 0]
    if kind == "power_user":  # heavy but legitimate (statement export, bots like uptime monitors)
        n = ri(80, 300)
        return [n, u(30, 120), ri(15, 60), u(.03, .25), 0, 0, ri(0, 4), ri(1, 2), 0, 0, u(.5, 6), 0, 0, 0]
    if kind == "scanner":
        n = ri(40, 600)
        return [n, u(120, 1800), ri(30, 500), u(.4, .95), u(.15, .6), int(rng.random() < .7),
                ri(0, 3), ri(1, 3), ri(0, 5), ri(0, 8), u(.01, .5), 0, ri(1, 12), ri(0, 6)]
    if kind == "bruteforce":
        n = ri(30, 500)
        return [n, u(60, 900), ri(1, 4), u(0, .1), u(0, .1), int(rng.random() < .3), ri(20, 400), 2,
                ri(0, 3), 0, u(.05, 1), 0, ri(0, 3), ri(0, 3)]
    if kind == "injector":
        n = ri(15, 200)
        return [n, u(30, 400), ri(3, 30), u(.1, .5), u(.05, .3), int(rng.random() < .5), ri(0, 30), ri(2, 3),
                ri(5, 60), ri(0, 10), u(.05, 2), 0, ri(0, 6), ri(0, 2)]
    if kind == "agentic":
        n = ri(25, 250)
        return [n, u(15, 150), ri(15, 120), u(.15, .5), u(.1, .45), int(rng.random() < .1), ri(2, 30),
                ri(2, 4), ri(1, 12), ri(0, 6), u(.3, 6), ri(1, 6), ri(1, 10), ri(1, 8)]
    if kind == "stealth":  # low-and-slow
        n = ri(8, 40)
        return [n, u(2, 10), ri(5, 30), u(.3, .7), u(.2, .6), 0, ri(0, 4), ri(1, 2), ri(0, 3), ri(0, 2),
                u(5, 60), ri(0, 2), ri(0, 3), ri(0, 2)]
    raise ValueError(kind)


def generate_dataset(n=6000, seed=7):
    rng = np.random.default_rng(seed)
    kinds = (["benign"] * 42 + ["power_user"] * 8 + ["scanner"] * 14 + ["bruteforce"] * 9 +
             ["injector"] * 9 + ["agentic"] * 11 + ["stealth"] * 7)
    X, y = [], []
    for _ in range(n):
        k = kinds[int(rng.integers(0, len(kinds)))]
        row = np.array(_persona(rng, k), dtype=float)
        row *= rng.normal(1, 0.06, size=row.shape)  # measurement noise
        label = 0 if k in ("benign", "power_user") else 1
        if rng.random() < .015:  # label noise so metrics are not trivially 1.0
            label ^= 1
        X.append(np.clip(row, 0, None))
        y.append(label)
    return np.array(X), np.array(y)


def _models():
    models = {
        "Random Forest": RandomForestClassifier(n_estimators=150, random_state=1, n_jobs=-1),
        "SVM": make_pipeline(StandardScaler(), SVC(probability=True, random_state=1)),
        "Neural Network": make_pipeline(StandardScaler(), MLPClassifier((32, 16), max_iter=500, random_state=1)),
    }
    if XGBClassifier is not None:
        models["Gradient Boosting (XGBoost)"] = XGBClassifier(n_estimators=150, max_depth=4, learning_rate=.1,
                                                              eval_metric="logloss", verbosity=0)
    else:
        models["Gradient Boosting"] = GradientBoostingClassifier(random_state=1)
    return models


class Detector:
    def __init__(self):
        self.models, self.metrics, self.primary = {}, [], None
        self.train_seconds = 0.0

    def train(self):
        t0 = time.time()
        X, y = generate_dataset()
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=.25, random_state=3, stratify=y)
        for name, model in _models().items():
            model.fit(Xtr, ytr)
            p = model.predict_proba(Xte)[:, 1]
            pred = (p >= .5).astype(int)
            self.models[name] = model
            self.metrics.append({
                "model": name,
                "accuracy": round(accuracy_score(yte, pred), 4),
                "precision": round(precision_score(yte, pred), 4),
                "recall": round(recall_score(yte, pred), 4),
                "f1": round(f1_score(yte, pred), 4),
                "roc_auc": round(roc_auc_score(yte, p), 4),
            })
        best = max(self.metrics, key=lambda m: m["f1"])
        self.primary = best["model"]
        self.train_seconds = round(time.time() - t0, 1)
        return self

    def predict(self, feature_vector):
        x = np.array([feature_vector], dtype=float)
        return float(self.models[self.primary].predict_proba(x)[0, 1])

    @property
    def primary_f1(self):
        return next(m["f1"] for m in self.metrics if m["model"] == self.primary)
