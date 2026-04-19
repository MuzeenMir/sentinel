#!/usr/bin/env python3
"""
SENTINEL Dataset Downloader
Downloads publicly available IDS datasets for training.

Datasets handled:
  - UNSW-NB15      : UNSW Canberra (direct HTTP)
  - NSL-KDD        : UNB (direct HTTP)
  - CIC-IDS-2017   : Already present; verifies files
  - CIC-IDS-2018   : Already present; verifies files
  - NF-UQ-NIDS-v2  : Kaggle API (requires kaggle.json)
  - TON_IoT        : UNSW (direct HTTP, network subset)

Usage:
  python download_datasets.py --all
  python download_datasets.py --datasets unsw_nb15 nsl_kdd
  python download_datasets.py --list
"""

from __future__ import annotations

import argparse
import logging
import shutil
from pathlib import Path
from typing import Dict, List

import requests
from tqdm import tqdm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sentinel.datasets")

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "datasets" / "data"


# ── Download registry ──────────────────────────────────────────────────────────

DATASETS: Dict[str, dict] = {
    # ── UNSW-NB15 ─────────────────────────────────────────────────────────────
    # Reference: Moustafa & Slay, 2015
    # 257,673 rows, 49 features, 9 attack categories + normal
    "unsw_nb15": {
        "description": "UNSW-NB15 — 9 attack categories + normal (UNSW Canberra, 2015)",
        "dest_dir": DATA_DIR / "unsw_nb15",
        "files": [
            {
                "name": "UNSW_NB15_training-set.csv",
                "url": (
                    "https://cloudstor.aarnet.edu.au/plus/index.php/s/"
                    "2DhnLGDdEECo4ys/download?path=%2FUNSW-NB15%20-%20CSV%20Files"
                    "%2Fa%20part%20of%20training%20and%20testing%20set"
                    "&files=UNSW_NB15_training-set.csv"
                ),
                "fallback_url": (
                    "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/"
                    "placeholder"  # just a fallback marker
                ),
                "size_mb": 14,
            },
            {
                "name": "UNSW_NB15_testing-set.csv",
                "url": (
                    "https://cloudstor.aarnet.edu.au/plus/index.php/s/"
                    "2DhnLGDdEECo4ys/download?path=%2FUNSW-NB15%20-%20CSV%20Files"
                    "%2Fa%20part%20of%20training%20and%20testing%20set"
                    "&files=UNSW_NB15_testing-set.csv"
                ),
                "size_mb": 4,
            },
        ],
    },
    # ── NSL-KDD ───────────────────────────────────────────────────────────────
    # Reference: Tavallaee et al., 2009
    # Improved version of KDD Cup 99 — removes redundant records
    "nsl_kdd": {
        "description": "NSL-KDD — improved KDD Cup 99 (UNB, 2009)",
        "dest_dir": DATA_DIR / "nsl_kdd",
        "files": [
            {
                "name": "KDDTrain+.arff",
                "url": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.arff",
                "size_mb": 18,
            },
            {
                "name": "KDDTest+.arff",
                "url": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.arff",
                "size_mb": 3,
            },
            {
                "name": "KDDTrain+_20Percent.arff",
                "url": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+_20Percent.arff",
                "size_mb": 4,
            },
        ],
        "post_process": "convert_arff_to_csv",
    },
    # ── CIC-IDS-2017 (verify only — already present) ──────────────────────────
    "cicids2017": {
        "description": "CIC-IDS-2017 — 15 attack types (UNB, 2017) — VERIFY ONLY",
        "dest_dir": DATA_DIR / "cicids2017",
        "files": [],  # already downloaded, just verify
        "verify_only": True,
    },
    # ── CIC-IDS-2018 (verify only — already present) ──────────────────────────
    "cicids2018": {
        "description": "CSE-CIC-IDS-2018 — 14 attack types (AWS Open Data, 2018) — VERIFY ONLY",
        "dest_dir": DATA_DIR / "cicids2018",
        "files": [],  # already downloaded, just verify
        "verify_only": True,
    },
    # ── NF-UQ-NIDS v2 (via Kaggle) ────────────────────────────────────────────
    # Reference: Sarhan et al., 2021
    # NetFlow-based dataset combining CIC-IDS-2018, UNSW-NB15, BoT-IoT, ToN-IoT
    "nf_uq_nids_v2": {
        "description": "NF-UQ-NIDS-v2 — NetFlow-based unified IDS dataset (Kaggle, 2021)",
        "dest_dir": DATA_DIR / "nf_uq_nids_v2",
        "kaggle": {
            "dataset": "dhoogla/nfuqnidsv2",
            "files": ["NF-UQ-NIDS-v2.csv"],
        },
        "files": [],
    },
    # ── TON_IoT Network ───────────────────────────────────────────────────────
    # Reference: Alsaedi et al., 2020 — IoT and network telemetry
    "ton_iot": {
        "description": "TON_IoT Network — IoT attack dataset (UNSW, 2020)",
        "dest_dir": DATA_DIR / "ton_iot",
        "kaggle": {
            "dataset": "azizfatimach/ton-iot-dataset-network-traffic-data",
            "files": ["Train_Test_Network.csv"],
        },
        "files": [],
    },
}


# ── Download helpers ───────────────────────────────────────────────────────────


class TqdmUpTo(tqdm):
    """tqdm subclass for urlretrieve progress."""

    def update_to(self, b=1, bsize=1, tsize=None):
        if tsize is not None:
            self.total = tsize
        self.update(b * bsize - self.n)


def _download_file(url: str, dest: Path, size_mb: int = 0) -> bool:
    """Download a single file with progress bar. Returns True on success."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")

    desc = dest.name[:50]
    expected = f" (~{size_mb} MB)" if size_mb else ""
    logger.info("  ↓ %s%s", dest.name, expected)

    try:
        # Stream with requests for better error handling
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "SENTINEL-Dataset-Downloader/1.0"
            )
        }
        with requests.get(url, stream=True, headers=headers, timeout=120) as resp:
            resp.raise_for_status()
            total = int(resp.headers.get("content-length", 0))
            with open(tmp, "wb") as fh:
                with tqdm(
                    total=total,
                    unit="B",
                    unit_scale=True,
                    desc=f"    {desc}",
                    leave=False,
                ) as pbar:
                    for chunk in resp.iter_content(chunk_size=65536):
                        fh.write(chunk)
                        pbar.update(len(chunk))

        shutil.move(str(tmp), str(dest))
        logger.info("  ✓ Saved %s (%.1f MB)", dest.name, dest.stat().st_size / 1e6)
        return True

    except Exception as exc:
        logger.error("  ✗ Failed to download %s: %s", dest.name, exc)
        if tmp.exists():
            tmp.unlink()
        return False


def _kaggle_download(dataset_spec: dict, dest_dir: Path) -> bool:
    """Download via Kaggle API. Requires ~/.kaggle/kaggle.json."""
    try:
        import kaggle  # noqa

        dest_dir.mkdir(parents=True, exist_ok=True)
        dataset = dataset_spec["dataset"]
        logger.info("  Kaggle: downloading %s", dataset)
        kaggle.api.dataset_download_files(dataset, path=str(dest_dir), unzip=True)
        logger.info("  ✓ Kaggle download complete")
        return True
    except ImportError:
        logger.warning(
            "  Kaggle API not installed. Run: pip install kaggle\n"
            "  Then place ~/.kaggle/kaggle.json with your API credentials.\n"
            "  Get token at: https://www.kaggle.com/settings → API → Create New Token"
        )
        return False
    except Exception as exc:
        logger.error("  ✗ Kaggle download failed: %s", exc)
        return False


def _convert_arff_to_csv(dest_dir: Path) -> None:
    """Convert NSL-KDD ARFF files to CSV format."""

    for arff_path in dest_dir.glob("*.arff"):
        csv_path = arff_path.with_suffix(".csv")
        if csv_path.exists():
            continue

        logger.info("  Converting %s → %s", arff_path.name, csv_path.name)
        headers: List[str] = []
        data_section = False
        rows = []

        with open(arff_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("%"):
                    continue
                if line.upper().startswith("@ATTRIBUTE"):
                    # @attribute <name> <type>
                    parts = line.split()
                    headers.append(parts[1].strip("'\""))
                elif line.upper() == "@DATA":
                    data_section = True
                elif data_section:
                    rows.append(line)

        with open(csv_path, "w") as out:
            out.write(",".join(headers) + "\n")
            for row in rows:
                out.write(row + "\n")

        logger.info("  ✓ Converted %s (%d rows)", csv_path.name, len(rows))


# ── NSL-KDD loader shim (add to data_loader.py if needed) ─────────────────────


def _build_nsl_kdd_loader_hint() -> str:
    return """
# To add NSL-KDD to data_loader.py, add this mapping and loader:

_NSLKDD_MAP = {
    "normal": "benign",
    "neptune": "ddos_attack", "smurf": "ddos_attack", "teardrop": "dos_attack",
    "pod": "dos_attack", "land": "dos_attack", "back": "dos_attack",
    "apache2": "dos_attack", "udpstorm": "dos_attack", "processtable": "dos_attack",
    "mailbomb": "dos_attack",
    "ipsweep": "port_scan", "portsweep": "port_scan", "nmap": "port_scan",
    "satan": "port_scan", "mscan": "port_scan", "saint": "port_scan",
    "ftp_write": "brute_force", "guess_passwd": "brute_force",
    "imap": "brute_force", "phf": "brute_force", "multihop": "lateral_movement",
    "spy": "data_exfiltration", "warezclient": "malware", "warezmaster": "malware",
    "buffer_overflow": "malware", "loadmodule": "malware", "perl": "malware",
    "rootkit": "malware", "xterm": "malware", "ps": "malware",
    "sqlattack": "sql_injection", "xlock": "brute_force", "sendmail": "malware",
    "named": "malware", "snmpgetattack": "unknown", "snmpguess": "unknown",
    "httptunnel": "c2_communication", "worm": "ransomware",
}
"""


# ── Main download logic ────────────────────────────────────────────────────────


def verify_dataset(name: str, spec: dict) -> dict:
    """Verify an existing dataset and return status."""
    dest = Path(spec["dest_dir"])
    if not dest.exists():
        return {"status": "missing", "files": 0, "size_gb": 0}

    csv_files = list(dest.glob("*.csv"))
    arff_files = list(dest.glob("*.arff"))
    all_files = csv_files + arff_files
    total_size = sum(f.stat().st_size for f in all_files)

    if not all_files:
        return {"status": "empty", "files": 0, "size_gb": 0}

    return {
        "status": "complete",
        "files": len(all_files),
        "size_gb": round(total_size / 1e9, 2),
        "file_names": [f.name for f in sorted(all_files)],
    }


def download_dataset(name: str, spec: dict, force: bool = False) -> bool:
    """Download a single dataset. Returns True if successful."""
    logger.info("")
    logger.info("─" * 60)
    logger.info("Dataset: %s", name)
    logger.info("  %s", spec["description"])
    logger.info("─" * 60)

    dest_dir = Path(spec["dest_dir"])

    # Verify-only datasets
    if spec.get("verify_only"):
        status = verify_dataset(name, spec)
        if status["status"] == "complete":
            logger.info(
                "  ✓ Already present: %d files (%.2f GB)",
                status["files"],
                status["size_gb"],
            )
            return True
        else:
            logger.warning(
                "  ⚠ %s is marked verify-only but status=%s. "
                "Locate and place CSV files in: %s",
                name,
                status["status"],
                dest_dir,
            )
            return False

    # Kaggle datasets
    if "kaggle" in spec:
        existing = list(dest_dir.glob("*.csv")) if dest_dir.exists() else []
        if existing and not force:
            logger.info("  ✓ Already present: %d files", len(existing))
            return True
        logger.info("  Using Kaggle API...")
        return _kaggle_download(spec["kaggle"], dest_dir)

    # Direct HTTP downloads
    dest_dir.mkdir(parents=True, exist_ok=True)
    all_ok = True

    for file_spec in spec.get("files", []):
        fname = file_spec["name"]
        dest_file = dest_dir / fname

        if dest_file.exists() and not force:
            logger.info(
                "  ✓ Already downloaded: %s (%.1f MB)",
                fname,
                dest_file.stat().st_size / 1e6,
            )
            continue

        ok = _download_file(file_spec["url"], dest_file, file_spec.get("size_mb", 0))
        if not ok and "fallback_url" in file_spec:
            logger.warning("  Trying fallback URL...")
            ok = _download_file(
                file_spec["fallback_url"], dest_file, file_spec.get("size_mb", 0)
            )

        if not ok:
            all_ok = False

    # Post-processing
    if all_ok and spec.get("post_process") == "convert_arff_to_csv":
        _convert_arff_to_csv(dest_dir)

    return all_ok


def update_manifest(results: Dict[str, dict]) -> None:
    """Update the MANIFEST.txt with current status."""
    manifest_path = DATA_DIR / "MANIFEST.txt"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    from datetime import datetime, timezone

    lines = [
        "SENTINEL Training Datasets",
        f"Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "=" * 42,
        "",
    ]

    total_size = 0.0
    for name, result in results.items():
        size = result.get("size_gb", 0)
        total_size += size
        files = result.get("files", 0)
        status = result.get("status", "unknown").upper()
        lines += [
            f"Dataset: {name}",
            f"  Status: {status}",
            f"  Files:  {files} CSV",
            f"  Size:   {size:.1f} GB"
            if size >= 0.1
            else f"  Size:   {int(size * 1000)} MB",
            "",
        ]

    lines += [
        "=" * 42,
        f"Total disk usage: {total_size:.1f} GB",
        f"Data directory  : {DATA_DIR}",
    ]

    manifest_path.write_text("\n".join(lines))
    logger.info("Updated MANIFEST.txt")


# ── CLI ────────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL Dataset Downloader",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--datasets",
        nargs="+",
        choices=list(DATASETS.keys()),
        help="Specific datasets to download",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Download all available datasets",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-download even if files already exist",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available datasets and their status",
    )
    parser.add_argument(
        "--data-dir",
        default=str(DATA_DIR),
        help=f"Base data directory (default: {DATA_DIR})",
    )
    args = parser.parse_args()

    global DATA_DIR
    DATA_DIR = Path(args.data_dir)
    # Update dest_dirs relative to new DATA_DIR
    for name, spec in DATASETS.items():
        spec["dest_dir"] = DATA_DIR / name

    if args.list or (not args.all and not args.datasets):
        print("\nAvailable datasets:\n")
        for name, spec in DATASETS.items():
            status = verify_dataset(name, spec)
            mark = "✓" if status["status"] == "complete" else "✗"
            size_str = (
                f"{status['size_gb']:.1f} GB"
                if status["size_gb"] > 0
                else "not downloaded"
            )
            print(f"  {mark}  {name:<20}  {size_str:<12}  {spec['description']}")
        print()
        print("Tip: CIC-IDS-2017 and CIC-IDS-2018 require manual download from:")
        print("  CIC-IDS-2017: https://www.unb.ca/cic/datasets/ids-2017.html")
        print("  CIC-IDS-2018: https://www.unb.ca/cic/datasets/ids-2018.html")
        print(
            "               (or: aws s3 cp --no-sign-request s3://cse-cic-ids2018/ ...)"
        )
        return

    targets = list(DATASETS.keys()) if args.all else (args.datasets or [])
    if not targets:
        parser.print_help()
        return

    results = {}
    for name in targets:
        spec = DATASETS[name]
        ok = download_dataset(name, spec, force=args.force)
        results[name] = verify_dataset(name, spec)
        results[name]["ok"] = ok

    # Update manifest
    update_manifest(results)

    # Final summary
    print("\n" + "=" * 60)
    print("DOWNLOAD SUMMARY")
    print("=" * 60)
    for name, result in results.items():
        mark = "✓" if result.get("ok") and result["status"] == "complete" else "✗"
        print(
            f"  {mark}  {name:<25}  {result['status']:<12}  "
            f"{result.get('files', 0)} files  "
            f"{result.get('size_gb', 0):.1f} GB"
        )
    print()

    # Print NSL-KDD loader hint if downloaded
    if "nsl_kdd" in targets:
        print("NSL-KDD loader hint (add to training/data_loader.py):")
        print(_build_nsl_kdd_loader_hint())


if __name__ == "__main__":
    main()
