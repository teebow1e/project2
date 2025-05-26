"""
apk_detector.py - single-file Android APK malware detector

Usage
-----
python apk_detector.py /path/to/app.apk

Requirements
------------
pip install tensorflow numpy
(plus gensim if you still need to generate embedding.npy)

Folder layout
-------------
project/
├── apk_detector.py
└── artifacts/
    ├── model.h5
    └── embedding.npy
"""
import os
import struct
import sys
import tempfile
import pathlib
import argparse
from zipfile import ZipFile

os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '1'


import numpy as np
import tensorflow as tf
from gensim.models import KeyedVectors

# ──────────────────────────────────────────────────────────────────────────
# Constant parameters (match training)
BYTE_LIMIT       = 65536
MODEL_PATH       = "./word2vec_model.h5"
EMBED_PATH       = "./custom_bytecode_word2vec.kv"
LABELS           = {0: "Benign", 1: "Malware"}

# ──────────────────────────────────────────────────────────────────────────

MODEL = tf.keras.models.load_model(MODEL_PATH)
# MODEL.summary()

word_vectors = KeyedVectors.load(EMBED_PATH)
EMBED = np.zeros((256, word_vectors.vector_size))

for i in range(256):
    bytecode_str = str(i)
    EMBED[i] = word_vectors[bytecode_str]

# print(f"Embedding Matrix Shape: {EMBED.shape}")
# print(f"Embedding Dimension: {EMBED.shape[1]}")

# ──────────────────────────────────────────────────────────────────────────
# Helper functions
def _unpack_dex(apk_path: str, dst_dir: str) -> str:
    with ZipFile(apk_path) as zf:
        zf.extract("classes.dex", path=dst_dir)
    return os.path.join(dst_dir, "classes.dex")


def _extract_data_section(dex_path: str) -> bytes:
    """
    Return the raw bytes of the DEX *data* section (trim / pad to BYTE_LIMIT).
    """
    with open(dex_path, "rb") as f:
        header = f.read(0x70)                              # DEX header
        data_size, data_off = struct.unpack_from("<II", header, 0x68)
        f.seek(data_off)
        blob = f.read(data_size)

    return blob[:BYTE_LIMIT].ljust(BYTE_LIMIT, b"\x00")


def _load_bin(bin_path: str) -> bytes:
    with open(bin_path, "rb") as f:
        blob = f.read()
    return blob[:BYTE_LIMIT].ljust(BYTE_LIMIT, b"\x00")

def _bytes_to_tensor(raw: bytes) -> np.ndarray:
    byte_idx = np.frombuffer(raw, dtype=np.uint8, count=BYTE_LIMIT)
    return EMBED[byte_idx]                           # (65 536, 32)

def _predict(arr: np.ndarray) -> tuple[str, float]:
    probs = MODEL.predict(np.expand_dims(arr, 0), verbose=0)[0]
    idx   = int(np.argmax(probs))
    return LABELS[idx], float(probs[idx])


def scan_apk(apk_path: str) -> tuple[str, float]:
    """
    Run full pipeline and return (label, confidence).
    """
    with tempfile.TemporaryDirectory() as tmp:
        dex = _unpack_dex(apk_path, tmp)
        raw = _extract_data_section(dex)

    sample = np.expand_dims(_bytes_to_tensor(raw), 0)      # (1, 65 536, 32)
    probs  = MODEL.predict(sample, verbose=0)[0]
    idx    = int(np.argmax(probs))
    return LABELS[idx], float(probs[idx])

def scan_bin(bin_path: str) -> tuple[str, float]:
    raw = _load_bin(bin_path)
    return _predict(_bytes_to_tensor(raw))



# ──────────────────────────────────────────────────────────────────────────
# CLI
def main() -> None:
    parser = argparse.ArgumentParser(description="APK / BIN malware detector")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--apk", metavar="FILE", help="scan an APK file")
    group.add_argument("--bin", metavar="FILE", help="scan a data_section.bin")
    args = parser.parse_args()

    file_path = args.apk or args.bin
    if not pathlib.Path(file_path).exists():
        sys.exit("File not found.")

    if args.apk:
        label, conf = scan_apk(file_path)
    else:
        label, conf = scan_bin(file_path)

    print(f"{pathlib.Path(file_path).name}  →  {label}  ({conf:.2%} confidence)")


if __name__ == "__main__":
    main()
