"""
UNIQUE FEATURE: Behavioral DNA Profiler
- Tracks how each agent's response patterns evolve over time
- Detects "personality drift" - when an agent starts behaving unusually
- Computes a behavioral fingerprint (DNA) for each agent session
- Flags anomalies before they become security incidents
"""

import time
import hashlib
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

@dataclass
class BehaviorSample:
    timestamp: float
    agent: str
    query_length: int
    response_length: int
    risk_score: float
    category: str
    response_time_ms: int
    sentiment_score: float  # -1 to 1
    formality_score: float  # 0 to 1
    certainty_score: float  # 0 to 1

class BehavioralDNAProfiler:
    """
    Builds a behavioral fingerprint for each agent.
    Detects drift when current behavior deviates >2 sigma from baseline.
    """
    def __init__(self, window_size: int = 50):
        self.window_size = window_size
        self.agent_samples: dict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))
        self.baselines: dict[str, dict] = {}
        self.drift_alerts: list[dict] = []

    def _compute_sentiment(self, text: str) -> float:
        positive = ["help", "happy", "great", "excellent", "good", "success", "approved", "completed"]
        negative = ["error", "fail", "denied", "blocked", "reject", "issue", "problem", "cannot"]
        text_lower = text.lower()
        pos = sum(1 for w in positive if w in text_lower)
        neg = sum(1 for w in negative if w in text_lower)
        total = pos + neg or 1
        return round((pos - neg) / total, 3)

    def _compute_formality(self, text: str) -> float:
        informal = ["gonna", "wanna", "kinda", "sorta", "yeah", "nope", "hey", "ok", "cool"]
        formal = ["pursuant", "herein", "aforementioned", "accordance", "thereof", "whereas"]
        text_lower = text.lower()
        inf_count = sum(1 for w in informal if w in text_lower)
        form_count = sum(1 for w in formal if w in text_lower)
        return round(min(1.0, (form_count * 0.3 + 0.5 - inf_count * 0.1)), 3)

    def _compute_certainty(self, text: str) -> float:
        uncertain = ["might", "maybe", "perhaps", "possibly", "could be", "not sure", "unclear"]
        certain = ["will", "must", "always", "never", "confirmed", "required", "mandatory"]
        text_lower = text.lower()
        unc = sum(1 for w in uncertain if w in text_lower)
        cert = sum(1 for w in certain if w in text_lower)
        return round(min(1.0, max(0.0, 0.5 + (cert - unc) * 0.1)), 3)

    def _compute_baseline(self, samples: list) -> dict:
        if not samples:
            return {}
        def mean(vals): return sum(vals) / len(vals)
        def std(vals):
            m = mean(vals)
            return math.sqrt(sum((v - m) ** 2 for v in vals) / len(vals)) if len(vals) > 1 else 0.1

        metrics = ["risk_score", "response_time_ms", "response_length", "sentiment_score", "formality_score", "certainty_score"]
        baseline = {}
        for m in metrics:
            vals = [getattr(s, m) for s in samples]
            baseline[m] = {"mean": round(mean(vals), 4), "std": round(max(std(vals), 0.01), 4)}
        return baseline

    def record(self, agent: str, query: str, response: str, risk_score: float, category: str, response_time_ms: int):
        sample = BehaviorSample(
            timestamp=time.time(),
            agent=agent,
            query_length=len(query),
            response_length=len(response),
            risk_score=risk_score,
            category=category,
            response_time_ms=response_time_ms,
            sentiment_score=self._compute_sentiment(response),
            formality_score=self._compute_formality(response),
            certainty_score=self._compute_certainty(response),
        )
        self.agent_samples[agent].append(sample)

        # Recompute baseline every 10 samples
        samples = list(self.agent_samples[agent])
        if len(samples) >= 5 and len(samples) % 5 == 0:
            self.baselines[agent] = self._compute_baseline(samples[:-3])

        # Detect drift using last 3 samples vs baseline
        if agent in self.baselines and len(samples) >= 8:
            self._detect_drift(agent, sample)

    def _detect_drift(self, agent: str, sample: BehaviorSample):
        baseline = self.baselines[agent]
        drift_metrics = []

        for metric in ["risk_score", "sentiment_score", "formality_score"]:
            if metric not in baseline:
                continue
            val = getattr(sample, metric)
            mean = baseline[metric]["mean"]
            std = baseline[metric]["std"]
            z_score = abs(val - mean) / std if std > 0 else 0
            if z_score > 2.5:
                drift_metrics.append({"metric": metric, "z_score": round(z_score, 2), "current": val, "expected": mean})

        if drift_metrics:
            alert = {
                "timestamp": datetime.utcnow().isoformat(),
                "agent": agent,
                "drift_detected": True,
                "drift_metrics": drift_metrics,
                "severity": "HIGH" if len(drift_metrics) >= 2 else "MEDIUM",
                "dna_fingerprint": self._compute_dna(agent),
            }
            self.drift_alerts.append(alert)

    def _compute_dna(self, agent: str) -> str:
        """Generate a behavioral fingerprint hash for the agent"""
        samples = list(self.agent_samples[agent])
        if not samples:
            return "NO_DATA"
        feature_str = f"{agent}:{len(samples)}:{sum(s.risk_score for s in samples[-5:]):.3f}:{sum(s.sentiment_score for s in samples[-5:]):.3f}"
        return hashlib.sha256(feature_str.encode()).hexdigest()[:16].upper()

    def get_agent_dna(self, agent: str) -> dict:
        samples = list(self.agent_samples[agent])
        if not samples:
            return {"agent": agent, "status": "NO_DATA", "samples": 0}
        baseline = self.baselines.get(agent, {})
        recent = samples[-5:] if len(samples) >= 5 else samples
        return {
            "agent": agent,
            "dna_fingerprint": self._compute_dna(agent),
            "total_samples": len(samples),
            "baseline": baseline,
            "current_behavior": {
                "avg_risk": round(sum(s.risk_score for s in recent) / len(recent), 3),
                "avg_sentiment": round(sum(s.sentiment_score for s in recent) / len(recent), 3),
                "avg_formality": round(sum(s.formality_score for s in recent) / len(recent), 3),
                "avg_certainty": round(sum(s.certainty_score for s in recent) / len(recent), 3),
                "avg_response_ms": round(sum(s.response_time_ms for s in recent) / len(recent)),
            },
            "drift_alerts": [a for a in self.drift_alerts if a["agent"] == agent],
            "status": "DRIFTING" if any(a["agent"] == agent for a in self.drift_alerts[-10:]) else "STABLE",
        }

    def get_all_dna(self) -> list[dict]:
        agents = list(self.agent_samples.keys())
        return [self.get_agent_dna(a) for a in agents]

    def get_drift_alerts(self) -> list[dict]:
        return self.drift_alerts[-20:]

dna_profiler = BehavioralDNAProfiler()
