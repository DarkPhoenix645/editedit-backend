from __future__ import annotations

import logging
import math
import pickle
from datetime import datetime
from pathlib import Path

from river import anomaly as river_anomaly

from app.core.config import BASE_DIR, settings

logger = logging.getLogger("forensiq.ml.anomaly")

PICKLE_VERSION = 2
ANOMALY_N_TREES = 15
ANOMALY_WINDOW_SIZE = 50


def _model_path() -> Path:
    if settings.ANOMALY_MODEL_PATH:
        return Path(settings.ANOMALY_MODEL_PATH)
    return BASE_DIR / "cold_storage" / "halfspace_model.pkl"


def _warmup_threshold() -> int:
    return settings.ANOMALY_WARMUP_THRESHOLD


class AnomalyDetector:
    """Streaming anomaly detector wrapping River HalfSpaceTrees."""

    def __init__(self) -> None:
        self.model = river_anomaly.HalfSpaceTrees(
            n_trees=ANOMALY_N_TREES,
            height=8,
            window_size=ANOMALY_WINDOW_SIZE,
            seed=42,
        )
        self.events_seen = 0
        self.is_calibrating = True
        self.WARMUP_THRESHOLD = _warmup_threshold()
        self.load()

    def _extract_and_clean(self, features: dict) -> dict:
        ts_str = features.get("timestamp")
        try:
            if ts_str:
                ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
                hour = ts.hour
            else:
                hour = datetime.utcnow().hour
        except Exception:
            hour = datetime.utcnow().hour

        outcome = features.get("outcome")
        is_failed = 1 if outcome == "failure" else 0

        metadata = features.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}

        try:
            logon_type = int(metadata.get("logon_type", 2))
        except (ValueError, TypeError):
            logon_type = 2

        try:
            bytes_sent = float(metadata.get("bytes_sent", 0))
            bytes_sent_log = math.log1p(bytes_sent)
        except (ValueError, TypeError):
            bytes_sent_log = 0.0

        src_ip = features.get("source_ip")
        dst_ip = features.get("dest_ip")
        is_remote = 1 if src_ip != dst_ip else 0

        trust_tier = features.get("trust_tier")
        trust_map = {
            "kernel": 1.0,
            "iam": 0.95,
            "os": 0.85,
            "application": 0.6,
            "cloud": 0.65,
            "iot": 0.3,
            "unknown": 0.1,
        }
        trust_tier_num = trust_map.get(trust_tier, 0.7)

        action = features.get("action", "")
        action_hash = hash(str(action)) % 1000
        user = features.get("user_id", "")
        user_hash = hash(str(user)) % 1000

        return {
            "hour_of_day": hour,
            "is_failed": is_failed,
            "logon_type": logon_type,
            "is_remote": is_remote,
            "trust_tier_num": trust_tier_num,
            "bytes_sent": bytes_sent_log,
            "action_hash": action_hash,
            "user_hash": user_hash,
        }

    def score_event(self, features: dict) -> float:
        features_clean = self._extract_and_clean(features)
        self.model.learn_one(features_clean)
        self.events_seen += 1

        if self.is_calibrating:
            if self.events_seen >= self.WARMUP_THRESHOLD:
                self.is_calibrating = False
                self.save()
                logger.info("Anomaly engine exited calibration after %d events", self.events_seen)
            return 0.0

        score = self.model.score_one(features_clean)
        if self.events_seen % 10_000 == 0:
            self.save()
        logger.debug("Event #%d scored %.4f", self.events_seen, score)
        return score

    def feature_contributions(self, features: dict) -> dict[str, float]:
        features_clean = self._extract_and_clean(features)
        full_score = self.model.score_one(features_clean)
        contributions: dict[str, float] = {}
        for key in features_clean:
            reduced = {k: v for k, v in features_clean.items() if k != key}
            if reduced:
                partial_score = self.model.score_one(reduced)
                contributions[key] = round(full_score - partial_score, 6)
            else:
                contributions[key] = round(full_score, 6)
        return contributions

    def save(self, path: Path | None = None) -> None:
        model_path = path or _model_path()
        model_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": PICKLE_VERSION,
            "model": self.model,
            "events_seen": self.events_seen,
            "is_calibrating": self.is_calibrating,
            "warmup_threshold": self.WARMUP_THRESHOLD,
        }
        with open(model_path, "wb") as f:
            pickle.dump(payload, f)
        logger.info(
            "Model saved to %s (events_seen=%d, calibrating=%s)",
            model_path,
            self.events_seen,
            self.is_calibrating,
        )

    def load(self, path: Path | None = None) -> None:
        model_path = path or _model_path()
        if not model_path.exists():
            logger.warning("No model snapshot at %s — using fresh model", model_path)
            return

        with open(model_path, "rb") as f:
            data = pickle.load(f)

        if isinstance(data, dict) and data.get("version") == PICKLE_VERSION:
            self.model = data["model"]
            self.events_seen = int(data.get("events_seen", 0))
            self.is_calibrating = bool(data.get("is_calibrating", False))
            stored_thr = int(data.get("warmup_threshold", self.WARMUP_THRESHOLD))
            self.WARMUP_THRESHOLD = stored_thr
            if self.events_seen >= self.WARMUP_THRESHOLD:
                self.is_calibrating = False
            logger.info(
                "Loaded anomaly snapshot v%s from %s (events_seen=%d, calibrating=%s, threshold=%d)",
                PICKLE_VERSION,
                model_path,
                self.events_seen,
                self.is_calibrating,
                self.WARMUP_THRESHOLD,
            )
            return

        self.model = data
        self.is_calibrating = False
        logger.info("Loaded legacy HalfSpaceTrees pickle from %s (treating as calibrated)", model_path)
