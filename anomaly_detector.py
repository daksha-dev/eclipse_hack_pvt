"""
anomaly_detector.py - IoT Trust & Drift Analytics System

Dual-model anomaly detection combining a static Isolation Forest with an
adaptive Half-Space Trees detector.

Design rationale
----------------
* **Isolation Forest (IF)** is trained once on the burn-in baseline and then
  frozen.  It provides a stable reference for "what normal looked like at
  deployment time".  Because it never updates, its scores remain anchored to
  the original distribution -- useful for detecting both sudden attacks and
  slow drifts away from baseline.  It receives the higher blending weight
  (default 0.6) because batch-trained models are more reliable on
  pre-collected network flow features.

* **Half-Space Trees (HST)** is an online/streaming anomaly detector (from
  the River library) that continuously adapts.  After each window is scored
  it ingests the new data via ``learn_one``, so its internal reference
  distribution tracks the recent past.  This makes it sensitive to abrupt
  behavioural shifts but it needs time to converge, hence the lower weight
  (default 0.4).

* The two raw scores are blended with configurable weights and then smoothed
  with a short moving average (default 3 windows) to suppress single-window
  noise spikes.  The smoothed score is what downstream modules (trust engine,
  drift detector) consume.

Normalisation
-------------
Scikit-learn's ``decision_function`` returns a signed float where *negative*
values are anomalous and *positive* values are normal.  We negate and
min-max-scale this into [0, 1] so that 0 = perfectly normal and 1 = extreme
anomaly, matching the HST score semantics and making the two models directly
comparable.

All features are standardised (zero-mean, unit-variance) using a
``StandardScaler`` fit on the burn-in data.  This prevents high-magnitude
features (e.g. total_bytes) from dominating the Isolation Forest splits.
"""

from collections import deque
from typing import Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from river.anomaly import HalfSpaceTrees

from feature_engineer import FEATURE_NAMES


# ── Helper functions ─────────────────────────────────────────────────────────


def get_feature_names_22() -> List[str]:
    """
    Return the canonical ordered list of 22 feature names produced by
    ``feature_engineer.extract_features``.

    Useful when converting between numpy arrays (positional) and
    dictionaries (named) that River expects.
    """
    return list(FEATURE_NAMES)


def convert_array_to_dict(
    feature_array: np.ndarray,
    feature_names: Optional[List[str]] = None,
) -> Dict[str, float]:
    """
    Convert a 1-D numpy feature array into a ``{name: value}`` dictionary
    suitable for River models.

    Parameters
    ----------
    feature_array : np.ndarray
        Shape ``(22,)`` or ``(1, 22)`` feature vector.
    feature_names : list of str, optional
        Column names.  Defaults to ``FEATURE_NAMES``.

    Returns
    -------
    dict[str, float]
    """
    if feature_names is None:
        feature_names = FEATURE_NAMES

    arr = np.asarray(feature_array, dtype=float).ravel()
    return {name: float(arr[i]) for i, name in enumerate(feature_names)}


def normalize_if_score(raw_score: float, offset: float, scale: float) -> float:
    """
    Convert a scikit-learn ``decision_function`` value to a 0-1 anomaly
    score.

    Scikit-learn convention:
        * Large positive  -> clearly normal
        * Near zero       -> borderline
        * Negative        -> anomalous

    We negate so that higher = more anomalous, then apply min-max scaling
    derived from the burn-in scores (``offset`` and ``scale``).

    Parameters
    ----------
    raw_score : float
        Output of ``IsolationForest.decision_function`` for one sample.
    offset : float
        The minimum negated score observed during burn-in (used as the
        "zero" anchor).
    scale : float
        The range (max - min) of negated burn-in scores.

    Returns
    -------
    float
        Anomaly score in [0, 1].
    """
    negated = -raw_score
    if scale == 0:
        return 0.0
    normalized = (negated - offset) / scale
    return float(np.clip(normalized, 0.0, 1.0))


# ── Isolation Forest wrapper ─────────────────────────────────────────────────


class IsolationForestModel:
    """
    Static anomaly detector trained once on burn-in data and then frozen.

    After ``train()`` is called the model never updates, so its definition
    of "normal" is permanently anchored to the baseline period.
    """

    def __init__(self, config: dict) -> None:
        """
        Parameters
        ----------
        config : dict
            Full parsed config.yaml.  Reads from ``config['models']['isolation_forest']``.
        """
        if_cfg = config["models"]["isolation_forest"]

        self._model = IsolationForest(
            n_estimators=if_cfg.get("n_estimators", 100),
            contamination=if_cfg.get("contamination", 0.05),
            random_state=if_cfg.get("random_state", 42),
        )
        self._scaler = StandardScaler()
        self._trained = False

        # Min-max anchors for normalising decision_function output
        self._norm_offset: float = 0.0
        self._norm_scale: float = 1.0

    @property
    def is_trained(self) -> bool:
        return self._trained

    def train(self, burn_in_features: np.ndarray) -> None:
        """
        Fit on burn-in feature matrix and freeze.

        Parameters
        ----------
        burn_in_features : np.ndarray
            Shape ``(n_windows, 22)`` -- one row per burn-in window.
        """
        X = np.asarray(burn_in_features, dtype=float)
        if X.ndim == 1:
            X = X.reshape(1, -1)

        # Fit scaler on baseline so all future scores use the same transform
        X_scaled = self._scaler.fit_transform(X)

        self._model.fit(X_scaled)

        # Derive normalisation anchors from burn-in scores
        raw_scores = self._model.decision_function(X_scaled)
        negated = -raw_scores
        self._norm_offset = float(negated.min())
        self._norm_scale = float(negated.max() - negated.min())
        if self._norm_scale == 0:
            self._norm_scale = 1.0
        if self._norm_scale < 0.1:
            self._norm_scale = 0.5

        self._trained = True

    def score(self, features: np.ndarray) -> float:
        """
        Score a single feature vector.

        Parameters
        ----------
        features : np.ndarray
            Shape ``(22,)`` or ``(1, 22)``.

        Returns
        -------
        float
            Anomaly score in [0, 1] where 0 = normal, 1 = anomaly.
        """
        if not self._trained:
            return 0.0

        X = np.asarray(features, dtype=float).reshape(1, -1)
        X_scaled = self._scaler.transform(X)
        raw = float(self._model.decision_function(X_scaled)[0])
        return normalize_if_score(raw, self._norm_offset, self._norm_scale)


# ── Half-Space Trees wrapper ─────────────────────────────────────────────────


class HalfSpaceTreesModel:
    """
    Adaptive streaming anomaly detector that continuously learns.

    Wraps River's ``HalfSpaceTrees``.  After each window is scored the
    caller should invoke ``update()`` so the model tracks the evolving
    data distribution.
    """

    def __init__(self, config: dict) -> None:
        """
        Parameters
        ----------
        config : dict
            Full parsed config.yaml.  Reads from ``config['models']['halfspacetrees']``.
        """
        hst_cfg = config["models"]["halfspacetrees"]

        self._model = HalfSpaceTrees(
            n_trees=hst_cfg.get("n_trees", 25),
            height=hst_cfg.get("height", 6),
            window_size=hst_cfg.get("window_size", 30),
        )

    @staticmethod
    def _numeric_only(d: Dict[str, float]) -> Dict[str, float]:
        """Strip non-numeric entries (e.g. ports_used list) before River."""
        return {k: v for k, v in d.items() if isinstance(v, (int, float))}

    def score(self, features_dict: Dict[str, float]) -> float:
        """
        Score a single observation.

        Parameters
        ----------
        features_dict : dict[str, float]
            Feature name -> value mapping (River's expected input format).

        Returns
        -------
        float
            Anomaly score in [0, 1].  River's HST already returns scores
            in this range (higher = more anomalous).
        """
        raw = self._model.score_one(self._numeric_only(features_dict))
        return float(np.clip(raw, 0.0, 1.0))

    def update(self, features_dict: Dict[str, float]) -> None:
        """
        Update the model with a new observation (called after scoring).

        Parameters
        ----------
        features_dict : dict[str, float]
            Same format as ``score()``.
        """
        self._model.learn_one(self._numeric_only(features_dict))


# ── Dual-model orchestrator ─────────────────────────────────────────────────


class DualModelDetector:
    """
    Orchestrates Isolation Forest and Half-Space Trees into a single
    anomaly scoring pipeline.

    Workflow per window
    -------------------
    1. ``score(features_dict)``  -- get blended, smoothed anomaly score.
    2. ``update_adaptive(features_dict)`` -- feed the window to HST.

    The caller (typically ``trust_engine``) drives this loop.
    """

    def __init__(self, config: dict) -> None:
        """
        Parameters
        ----------
        config : dict
            Full parsed config.yaml.
        """
        self._if_model = IsolationForestModel(config)
        self._hst_model = HalfSpaceTreesModel(config)

        self._if_weight: float = config["models"]["isolation_forest"].get("weight", 0.6)
        self._hst_weight: float = config["models"]["halfspacetrees"].get("weight", 0.4)

        # Moving-average buffer for smoothing the blended score.
        # Smoothing suppresses single-window noise spikes that would
        # otherwise cause unnecessary trust penalties.
        smoothing_size = config.get("anomaly", {}).get("smoothing_window", 3)
        self._smoothing_buf: deque = deque(maxlen=smoothing_size)

        # Full history of smoothed scores (consumed by drift detector / ADWIN)
        self._score_history: List[float] = []

        # Per-model history for disagreement detection
        self._if_history: List[float] = []
        self._hst_history: List[float] = []

    # ── training / priming ───────────────────────────────────────────

    def train_static(self, burn_in_features: np.ndarray) -> None:
        """
        Train the Isolation Forest on burn-in feature matrix and freeze it.

        Parameters
        ----------
        burn_in_features : np.ndarray
            Shape ``(n_windows, 22)``.
        """
        self._if_model.train(burn_in_features)

    def prime_adaptive(self, features_list: List[Dict[str, float]]) -> None:
        """
        Prime the Half-Space Trees with burn-in data so it has a
        reasonable reference distribution before live scoring begins.

        Each entry is fed via ``learn_one`` (no scoring happens here).

        Parameters
        ----------
        features_list : list of dict[str, float]
            One dict per burn-in window.
        """
        for feat_dict in features_list:
            self._hst_model.update(feat_dict)

    # ── scoring ──────────────────────────────────────────────────────

    def score(
        self, features_dict: Dict[str, float]
    ) -> Tuple[float, float, float]:
        """
        Produce a blended, smoothed anomaly score for one window.

        Steps
        -----
        1. Convert dict to array, score with IF.
        2. Score dict with HST.
        3. Blend:  ``combined = w_if * if_score + w_hst * hst_score``
        4. Append to moving-average buffer and compute smoothed value.

        Parameters
        ----------
        features_dict : dict[str, float]
            22-feature vector for the current window.

        Returns
        -------
        tuple of (if_score, hst_score, smoothed_combined)
            All values in [0, 1].
        """
        # IF expects a numpy array
        feature_array = np.array(
            [features_dict.get(name, 0.0) for name in FEATURE_NAMES],
            dtype=float,
        )
        if_score = self._if_model.score(feature_array)
        hst_score = self._hst_model.score(features_dict)

        # Weighted blend
        combined = self._if_weight * if_score + self._hst_weight * hst_score

        # Moving average smoothing.
        # Before the buffer is full the average uses whatever is available,
        # so the first window's smoothed score equals its raw combined score.
        self._smoothing_buf.append(combined)
        smoothed = float(np.mean(self._smoothing_buf))

        # Record histories
        self._if_history.append(if_score)
        self._hst_history.append(hst_score)
        self._score_history.append(smoothed)

        return (if_score, hst_score, smoothed)

    def update_adaptive(self, features_dict: Dict[str, float], trust_score: float = 100.0, device_id: str = "") -> None:
        """
        Feed the current window to HST so it adapts to the latest data,
        unless the device is severely compromised (trust_score < 30).

        Must be called **after** ``score()`` for the same window so the
        score reflects the model state *before* it sees the new data.

        Parameters
        ----------
        features_dict : dict[str, float]
        trust_score : float
            Current trust score of the device. If < 30, learning is skipped.
        device_id : str
            Identifier of the device.
        """
        if trust_score >= 30:
            self._hst_model.update(features_dict)

    # ── history access ───────────────────────────────────────────────

    def get_anomaly_history(self) -> List[float]:
        """
        Return the full list of smoothed anomaly scores produced so far.

        Used by the drift detector (ADWIN) which needs the score stream.
        """
        return list(self._score_history)

    def get_if_history(self) -> List[float]:
        """Return per-window Isolation Forest scores."""
        return list(self._if_history)

    def get_hst_history(self) -> List[float]:
        """Return per-window Half-Space Trees scores."""
        return list(self._hst_history)
