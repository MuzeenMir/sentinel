"""
Dataset loaders and preprocessors for SENTINEL training.

Supports:
  - CSE-CIC-IDS2018  (AWS Open Data)
  - CIC-IDS2017       (UNB)
  - UNSW-NB15          (UNSW Canberra)

Each loader reads raw CSVs, normalises column names, maps attack labels to
the SENTINEL ThreatCategory enum, engineers the 50-feature vector expected
by the detection models, and returns NumPy arrays ready for training.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

logger = logging.getLogger(__name__)

# ── SENTINEL label mapping ───────────────────────────────────────────────────

THREAT_CATEGORIES = [
    "benign", "malware", "dos_attack", "ddos_attack",
    "brute_force", "port_scan", "sql_injection", "xss",
    "data_exfiltration", "lateral_movement", "c2_communication",
    "ransomware", "unknown",
]

LABEL_TO_IDX: Dict[str, int] = {c: i for i, c in enumerate(THREAT_CATEGORIES)}

# CIC-IDS2018 label → SENTINEL category
_CICIDS2018_MAP: Dict[str, str] = {
    "Benign":               "benign",
    "Bot":                  "malware",
    "Brute Force -Web":     "brute_force",
    "Brute Force -XSS":     "xss",
    "DDOS attack-HOIC":     "ddos_attack",
    "DDOS attack-LOIC-UDP": "ddos_attack",
    "DDoS attacks-LOIC-HTTP": "ddos_attack",
    "DoS attacks-GoldenEye":"dos_attack",
    "DoS attacks-Hulk":     "dos_attack",
    "DoS attacks-SlowHTTPTest": "dos_attack",
    "DoS attacks-Slowloris":"dos_attack",
    "FTP-BruteForce":       "brute_force",
    "Infilteration":        "lateral_movement",
    "SQL Injection":        "sql_injection",
    "SSH-Bruteforce":       "brute_force",
}

# CIC-IDS2017 label → SENTINEL category
_CICIDS2017_MAP: Dict[str, str] = {
    "BENIGN":              "benign",
    "Bot":                 "malware",
    "DDoS":                "ddos_attack",
    "DoS GoldenEye":       "dos_attack",
    "DoS Hulk":            "dos_attack",
    "DoS Slowhttptest":    "dos_attack",
    "DoS slowloris":       "dos_attack",
    "FTP-Patator":         "brute_force",
    "Heartbleed":          "data_exfiltration",
    "Infiltration":        "lateral_movement",
    "PortScan":            "port_scan",
    "SSH-Patator":         "brute_force",
    "Web Attack \x96 Brute Force": "brute_force",
    "Web Attack – Brute Force": "brute_force",
    "Web Attack \x96 Sql Injection": "sql_injection",
    "Web Attack – Sql Injection": "sql_injection",
    "Web Attack \x96 XSS":  "xss",
    "Web Attack – XSS":     "xss",
}

# UNSW-NB15 attack_cat → SENTINEL category
_UNSW_MAP: Dict[str, str] = {
    "Normal":        "benign",
    "Fuzzers":       "unknown",
    "Analysis":      "unknown",
    "Backdoor":      "malware",
    "Backdoors":     "malware",
    "DoS":           "dos_attack",
    "Exploits":      "malware",
    "Generic":       "unknown",
    "Reconnaissance":"port_scan",
    "Shellcode":     "malware",
    "Worms":         "ransomware",
}

N_FEATURES = 50  # expected feature vector size


# ── Shared helpers ───────────────────────────────────────────────────────────

def _clean_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace from column names and lowercase them."""
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    return df


def _safe_numeric(df: pd.DataFrame) -> pd.DataFrame:
    """Coerce all non-label columns to numeric, replacing errors with NaN."""
    for col in df.columns:
        if df[col].dtype == object:
            try:
                df[col] = pd.to_numeric(df[col], errors="coerce")
            except Exception:
                pass
    return df


def _pad_or_truncate(X: np.ndarray, n_features: int = N_FEATURES) -> np.ndarray:
    """Ensure exactly n_features columns."""
    if X.shape[1] == n_features:
        return X
    if X.shape[1] > n_features:
        return X[:, :n_features]
    pad = np.zeros((X.shape[0], n_features - X.shape[1]), dtype=X.dtype)
    return np.hstack([X, pad])


# ── CIC-IDS2018 loader ──────────────────────────────────────────────────────

def load_cicids2018(
    data_dir: str,
    max_rows: Optional[int] = None,
) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """
    Load CSE-CIC-IDS2018 processed CSV files.
    Processes one file at a time to avoid OOM on large datasets.

    Returns (X, y, feature_names) where y contains integer class indices.
    """
    data_path = Path(data_dir) / "cicids2018"
    csv_files = sorted(data_path.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_path}")

    logger.info("Loading CIC-IDS2018 from %s (%d files)", data_path, len(csv_files))

    X_parts: List[np.ndarray] = []
    y_parts: List[np.ndarray] = []
    feature_names: List[str] = []
    label_col = None
    drop_cols = None
    feature_cols = None

    for fp in csv_files:
        logger.info("  Reading %s", fp.name)
        try:
            df = pd.read_csv(fp, encoding="utf-8", low_memory=False)
        except UnicodeDecodeError:
            df = pd.read_csv(fp, encoding="latin-1", low_memory=False)
        df = _clean_columns(df)

        if label_col is None:
            for candidate in ("label", "labels", "attack", "class"):
                if candidate in df.columns:
                    label_col = candidate
                    break
            if label_col is None:
                raise KeyError(f"Cannot find label column. Columns: {list(df.columns)}")
            df["_sentinel_label"] = (
                df[label_col].astype(str).str.strip().map(_CICIDS2018_MAP).fillna("unknown")
            )
            df["_sentinel_y"] = df["_sentinel_label"].map(LABEL_TO_IDX)
            drop_cols = [c for c in df.columns if c in (
                label_col, "_sentinel_label", "timestamp", "flow_id",
                "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
            ) or c.startswith("_sentinel")]
            feature_cols = [c for c in df.columns if c not in drop_cols]
            feature_names = list(feature_cols[:N_FEATURES])
            feature_names += [f"pad_{i}" for i in range(N_FEATURES - len(feature_names))]
        else:
            df["_sentinel_label"] = (
                df[label_col].astype(str).str.strip().map(_CICIDS2018_MAP).fillna("unknown")
            )
            df["_sentinel_y"] = df["_sentinel_label"].map(LABEL_TO_IDX)

        y_chunk = df["_sentinel_y"].values.astype(np.int64)
        df_features = df[feature_cols].copy()
        del df
        df_features = _safe_numeric(df_features)
        df_features.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_features.fillna(0, inplace=True)
        X_chunk = df_features.values.astype(np.float32)
        del df_features
        X_chunk = _pad_or_truncate(X_chunk, N_FEATURES)
        X_parts.append(X_chunk)
        y_parts.append(y_chunk)

    X = np.vstack(X_parts)
    y = np.concatenate(y_parts)
    del X_parts, y_parts

    if max_rows and len(X) > max_rows:
        rng = np.random.RandomState(42)
        idx = rng.choice(len(X), max_rows, replace=False)
        X = X[idx]
        y = y[idx]

    logger.info("CIC-IDS2018 loaded: X=%s  classes=%s", X.shape, np.unique(y).tolist())
    return X, y, feature_names[:N_FEATURES]


# ── CIC-IDS2017 loader ──────────────────────────────────────────────────────

def load_cicids2017(
    data_dir: str,
    max_rows: Optional[int] = None,
) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    data_path = Path(data_dir) / "cicids2017"
    csv_files = sorted(data_path.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files in {data_path}")

    logger.info("Loading CIC-IDS2017 from %s (%d files)", data_path, len(csv_files))

    frames: List[pd.DataFrame] = []
    for fp in csv_files:
        logger.info("  Reading %s", fp.name)
        try:
            chunk = pd.read_csv(fp, encoding="utf-8", low_memory=False)
        except UnicodeDecodeError:
            chunk = pd.read_csv(fp, encoding="latin-1", low_memory=False)
        chunk = _clean_columns(chunk)
        frames.append(chunk)

    df = pd.concat(frames, ignore_index=True)
    logger.info("Raw rows: %d", len(df))

    label_col = None
    for candidate in ("label", "labels"):
        if candidate in df.columns:
            label_col = candidate
            break
    if label_col is None:
        raise KeyError(f"Cannot find label column. Columns: {list(df.columns)}")

    df["_sentinel_label"] = (
        df[label_col].astype(str).str.strip().map(_CICIDS2017_MAP).fillna("unknown")
    )
    df["_sentinel_y"] = df["_sentinel_label"].map(LABEL_TO_IDX)

    drop_cols = [c for c in df.columns if c in (
        label_col, "timestamp", "flow_id",
        "source_ip", "source_port", "destination_ip", "destination_port",
        "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    ) or c.startswith("_sentinel")]
    feature_cols = [c for c in df.columns if c not in drop_cols]

    df_features = df[feature_cols].copy()
    df_features = _safe_numeric(df_features)
    df_features.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_features.fillna(0, inplace=True)

    y = df["_sentinel_y"].values.astype(np.int64)

    if max_rows and len(df_features) > max_rows:
        idx = np.random.RandomState(42).choice(len(df_features), max_rows, replace=False)
        df_features = df_features.iloc[idx]
        y = y[idx]

    X = df_features.values.astype(np.float32)
    X = _pad_or_truncate(X, N_FEATURES)
    feature_names = list(df_features.columns[:N_FEATURES])
    feature_names += [f"pad_{i}" for i in range(N_FEATURES - len(feature_names))]

    logger.info("CIC-IDS2017 loaded: X=%s  classes=%s", X.shape, np.unique(y).tolist())
    return X, y, feature_names[:N_FEATURES]


# ── UNSW-NB15 loader ────────────────────────────────────────────────────────

def load_unsw_nb15(
    data_dir: str,
    max_rows: Optional[int] = None,
) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    data_path = Path(data_dir) / "unsw_nb15"

    # Prefer the pre-split training/test files
    train_file = data_path / "UNSW_NB15_training-set.csv"
    test_file = data_path / "UNSW_NB15_testing-set.csv"

    if train_file.exists():
        logger.info("Loading UNSW-NB15 pre-split files")
        df_train = _clean_columns(pd.read_csv(train_file, low_memory=False))
        df_test = _clean_columns(pd.read_csv(test_file, low_memory=False))
        df = pd.concat([df_train, df_test], ignore_index=True)
    else:
        csv_files = sorted(data_path.glob("UNSW-NB15_*.csv")) or sorted(data_path.glob("*.csv"))
        if not csv_files:
            raise FileNotFoundError(f"No CSV files in {data_path}")
        frames = [_clean_columns(pd.read_csv(f, low_memory=False)) for f in csv_files]
        df = pd.concat(frames, ignore_index=True)

    logger.info("Raw rows: %d", len(df))

    # Identify label column
    label_col = None
    for candidate in ("attack_cat", "label", "attack_category"):
        if candidate in df.columns:
            label_col = candidate
            break
    if label_col is None:
        if "label" in df.columns:
            df["_sentinel_label"] = df["label"].apply(
                lambda x: "benign" if x == 0 else "unknown"
            )
        else:
            raise KeyError(f"Cannot find label column. Columns: {list(df.columns)}")
    else:
        df["_sentinel_label"] = (
            df[label_col].astype(str).str.strip().map(_UNSW_MAP).fillna("unknown")
        )

    df["_sentinel_y"] = df["_sentinel_label"].map(LABEL_TO_IDX)

    drop_cols = [c for c in df.columns if c in (
        label_col, "id", "attack_cat", "attack_category",
        "srcip", "sport", "dstip", "dsport",
    ) or c.startswith("_sentinel")]
    feature_cols = [c for c in df.columns if c not in drop_cols]

    df_features = df[feature_cols].copy()

    # One-hot encode categorical columns
    cat_cols = df_features.select_dtypes(include=["object"]).columns.tolist()
    if cat_cols:
        df_features = pd.get_dummies(df_features, columns=cat_cols, drop_first=True)

    df_features = _safe_numeric(df_features)
    df_features.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_features.fillna(0, inplace=True)

    y = df["_sentinel_y"].values.astype(np.int64)

    if max_rows and len(df_features) > max_rows:
        idx = np.random.RandomState(42).choice(len(df_features), max_rows, replace=False)
        df_features = df_features.iloc[idx]
        y = y[idx]

    X = df_features.values.astype(np.float32)
    X = _pad_or_truncate(X, N_FEATURES)
    feature_names = list(df_features.columns[:N_FEATURES])
    feature_names += [f"pad_{i}" for i in range(N_FEATURES - len(feature_names))]

    logger.info("UNSW-NB15 loaded: X=%s  classes=%s", X.shape, np.unique(y).tolist())
    return X, y, feature_names[:N_FEATURES]


# ── Unified loader ───────────────────────────────────────────────────────────

DATASET_LOADERS = {
    "cicids2018": load_cicids2018,
    "cicids2017": load_cicids2017,
    "unsw_nb15":  load_unsw_nb15,
}


def load_dataset(
    data_dir: str,
    dataset: str,
    max_rows: Optional[int] = None,
    test_size: float = 0.2,
    random_state: int = 42,
) -> Dict[str, np.ndarray | List[str]]:
    """
    Load a dataset and split into train/test.

    Returns dict with keys:
        X_train, X_test, y_train, y_test, feature_names
    """
    loader = DATASET_LOADERS.get(dataset)
    if loader is None:
        raise ValueError(f"Unknown dataset '{dataset}'. Choose from: {list(DATASET_LOADERS)}")

    X, y, feature_names = loader(data_dir, max_rows=max_rows)

    # Scale features
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y,
    )

    logger.info(
        "Dataset split: train=%d  test=%d  features=%d  classes=%d",
        len(X_train), len(X_test), X_train.shape[1], len(np.unique(y)),
    )

    return {
        "X_train": X_train.astype(np.float32),
        "X_test": X_test.astype(np.float32),
        "y_train": y_train,
        "y_test": y_test,
        "feature_names": feature_names,
        "scaler": scaler,
        "n_classes": len(np.unique(y)),
    }


def load_multiple_datasets(
    data_dir: str,
    datasets: List[str],
    max_rows_per_dataset: Optional[int] = None,
    test_size: float = 0.2,
    random_state: int = 42,
) -> Dict[str, np.ndarray | List[str]]:
    """
    Load and merge multiple datasets, then split into train/test.

    Each dataset is loaded independently and their rows are concatenated.
    """
    all_X, all_y = [], []
    feature_names = None

    for ds in datasets:
        X, y, fnames = DATASET_LOADERS[ds](data_dir, max_rows=max_rows_per_dataset)
        all_X.append(X)
        all_y.append(y)
        if feature_names is None:
            feature_names = fnames

    X = np.vstack(all_X)
    y = np.concatenate(all_y)

    # Shuffle
    rng = np.random.RandomState(random_state)
    perm = rng.permutation(len(X))
    X, y = X[perm], y[perm]

    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y,
    )

    logger.info(
        "Merged %d datasets: train=%d  test=%d  classes=%d",
        len(datasets), len(X_train), len(X_test), len(np.unique(y)),
    )

    return {
        "X_train": X_train.astype(np.float32),
        "X_test": X_test.astype(np.float32),
        "y_train": y_train,
        "y_test": y_test,
        "feature_names": feature_names,
        "scaler": scaler,
        "n_classes": len(np.unique(y)),
    }
