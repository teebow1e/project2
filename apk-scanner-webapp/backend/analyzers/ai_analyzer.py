import os
import struct
import tempfile
import pathlib
import logging
from zipfile import ZipFile

import numpy as np
import tensorflow as tf
from gensim.models import KeyedVectors

logger = logging.getLogger(__name__)

os.environ.setdefault("TF_ENABLE_ONEDNN_OPTS", "0")
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "1")

BYTE_LIMIT = 65_536
MODEL_PATH = "./models/word2vec_model.h5"
EMBED_PATH = "./models/custom_bytecode_word2vec.kv"
LABELS = {0: "Benign", 1: "Malware"}

try:
    _MODEL = tf.keras.models.load_model(MODEL_PATH)
except (IOError, OSError) as e:
    logger.error("Unable to load TensorFlow model: %s", e)
    raise

try:
    _WORD_VECTORS = KeyedVectors.load(EMBED_PATH)
except (IOError, OSError) as e:
    logger.error("Unable to load Word2Vec embedding: %s", e)
    raise

_EMBED = np.zeros((256, _WORD_VECTORS.vector_size), dtype=np.float32)
for i in range(256):
    _EMBED[i] = _WORD_VECTORS[str(i)]

def _unpack_dex(apk_path: str, dst_dir: str) -> str:
    """Extract classes.dex from an APK into *dst_dir* and return its path."""
    with ZipFile(apk_path) as zf:
        zf.extract("classes.dex", path=dst_dir)
    return os.path.join(dst_dir, "classes.dex")

def _extract_data_section(dex_path: str) -> bytes:
    """Return bytes of the DEX *data* section, padded / trimmed to BYTE_LIMIT."""
    with open(dex_path, "rb") as f:
        header = f.read(0x70)  # DEX header size
        data_size, data_off = struct.unpack_from("<II", header, 0x68)
        f.seek(data_off)
        blob = f.read(data_size)
    return blob[:BYTE_LIMIT].ljust(BYTE_LIMIT, b"\x00")


def _load_bin(bin_path: str) -> bytes:
    """Load an arbitrary binary blob from *bin_path* (padded / trimmed)."""
    with open(bin_path, "rb") as f:
        blob = f.read()
    return blob[:BYTE_LIMIT].ljust(BYTE_LIMIT, b"\x00")


def _bytes_to_tensor(raw: bytes) -> np.ndarray:
    """Convert raw bytes to embedded 2-D tensor expected by the network."""
    byte_idx = np.frombuffer(raw, dtype=np.uint8, count=BYTE_LIMIT)
    return _EMBED[byte_idx]


def _predict(arr: np.ndarray) -> tuple[str, float]:
    """Return (label, confidence) for a pre-embedded sample array."""
    probs = _MODEL.predict(np.expand_dims(arr, 0), verbose=0)[0]
    idx = int(np.argmax(probs))
    return LABELS[idx], float(probs[idx])


def _scan_apk(apk_path: str) -> tuple[str, float]:
    """Full pipeline for APK files - returns (label, confidence)."""
    with tempfile.TemporaryDirectory() as tmp:
        dex = _unpack_dex(apk_path, tmp)
        raw = _extract_data_section(dex)
    return _predict(_bytes_to_tensor(raw))


def _scan_bin(bin_path: str) -> tuple[str, float]:
    """Full pipeline for pre‑extracted binary data_section.bin files."""
    raw = _load_bin(bin_path)
    return _predict(_bytes_to_tensor(raw))

class AIAnalyzer:
    """Unified analyzer that wraps the on‑device ML model.

    The original heuristic‑based scoring has been removed per requirements -
    results are now driven solely by the neural network’s output.
    """

    def __init__(self):
        self.high_threshold = 0.70
        self.med_threshold = 0.40

    def analyze(self, file_path: str):
        """Analyze an APK or raw data_section.bin and return a report dict."""
        try:
            abs_path = pathlib.Path(file_path).expanduser().resolve(strict=True)
        except FileNotFoundError:
            raise FileNotFoundError(f"{file_path} does not exist")

        if abs_path.suffix.lower() == ".apk":
            label, conf = _scan_apk(str(abs_path))
        else:
            label, conf = _scan_bin(str(abs_path))

        report = self._build_report(abs_path.name, label, conf)
        return report

    def _build_report(self, filename: str, label: str, conf: float) -> dict:
        """Map raw model output onto the schema expected by callers."""
        risk_level = self._level_from_prediction(label, conf)
        risk_score = round(conf * 100, 1) if label == "Malware" else round((1 - conf) * 100, 1)

        findings = [
            f"ML model classified the sample as {label} with {conf:.2%} confidence."
        ]

        recommendation = (
            "This APK is likely malicious. Do NOT install it and submit for further analysis."
            if label == "Malware"
            else "APK appears benign. Standard security best‑practices still apply."
        )

        analysis_summary = (
            f"Machine‑learning based static analysis completed. Result: {label} (confidence: {conf:.2%}).\n"
        )

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "key_findings": findings,
            "recommendation": recommendation,
            "analysis_summary": analysis_summary,
            "confidence": round(conf * 100, 1),  # explicit confidence percentage
            "threat_categories": self._categorize(label),
        }

    def _level_from_prediction(self, label: str, conf: float) -> str:
        if label == "Malware":
            if conf >= self.high_threshold:
                return "HIGH"
            elif conf >= self.med_threshold:
                return "MEDIUM"
            else:
                return "LOW"
        else:  # Benign label
            # Invert thresholds - low confidence benign could still be suspicious.
            if conf <= (1 - self.high_threshold):
                return "HIGH"
            elif conf <= (1 - self.med_threshold):
                return "MEDIUM"
            else:
                return "LOW"

    @staticmethod
    def _categorize(label: str):
        if label == "Malware":
            return {"malware": ["ML detection"]}
        return {}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="APK / BIN malware detector (merged AIAnalyzer)")
    parser.add_argument("FILE", help="Path to *.apk or *.bin file to analyse")
    args = parser.parse_args()

    analyzer = AIAnalyzer()
    result = analyzer.analyze(args.FILE)

    print("\n=== Analysis report ===")
    for k, v in result.items():
        print(f"{k:16}: {v}")
