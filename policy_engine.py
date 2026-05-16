import re
import yaml
import time
import uuid
import json
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path

POLICY_PATH = Path(__file__).parent.parent / "policies" / "sentinelai_policies.yaml"

INTENT_CATEGORIES = {
    "data_retrieval": ["find", "search", "get", "fetch", "show", "list", "retrieve", "lookup"],
    "data_modification": ["update", "edit", "change", "modify", "set", "replace"],
    "data_creation": ["create", "add", "new", "generate", "draft", "write"],
    "data_deletion": ["delete", "remove", "purge", "drop", "erase"],
    "data_transmission": ["send", "email", "forward", "share", "export", "upload", "transfer"],
    "summarization": ["summarize", "summary", "tldr", "brief", "overview", "explain"],
    "analysis": ["analyze", "analyse", "compare", "evaluate", "assess", "report"],
    "code_execution": ["run", "execute", "deploy", "install", "pip", "bash", "shell"],
}

@dataclass
class AuditEvent:
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    agent: str = ""
    user_query: str = ""
    declared_intent: str = ""
    detected_intent: str = ""
    intent_mismatch: bool = False
    mismatch_score: float = 0.0
    action: str = "ALLOW"
    risk_score: float = 0.0
    policy_id: str = "default_allow"
    category: str = "BENIGN"
    pack: str = "DEFAULT"
    pii_detected: bool = False
    injection_detected: bool = False
    credential_detected: bool = False
    latency_ms: int = 0
    blocked: bool = False
    alert_fired: bool = False

    def to_dict(self):
        return asdict(self)

class PolicyEngine:
    def __init__(self):
        self.rules = []
        self.audit_log: list[AuditEvent] = []
        self.stats = {
            "total": 0, "blocked": 0, "allowed": 0,
            "quarantined": 0, "human_review": 0,
            "injections_caught": 0, "pii_caught": 0,
            "credential_caught": 0, "exfiltration_caught": 0,
            "intent_mismatches": 0,
        }
        self._load_policies()

    def _load_policies(self):
        try:
            with open(POLICY_PATH) as f:
                data = yaml.safe_load(f)
                self.rules = data.get("rules", [])
        except Exception as e:
            print(f"Policy load error: {e}")
            self.rules = []

    def _detect_pii(self, text: str) -> bool:
        patterns = [
            r"\b\d{3}-\d{2}-\d{4}\b",        # SSN
            r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",  # Credit card
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
            r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",  # Phone
        ]
        return any(re.search(p, text) for p in patterns)

    def _detect_intent(self, text: str) -> str:
        text_lower = text.lower()
        scores = {}
        for category, keywords in INTENT_CATEGORIES.items():
            score = sum(1 for kw in keywords if kw in text_lower)
            if score > 0:
                scores[category] = score
        return max(scores, key=scores.get) if scores else "unknown"

    def _compute_mismatch_score(self, declared: str, detected: str, action: str) -> tuple[bool, float]:
        if action in ("DENY", "QUARANTINE"):
            if declared in ("summarization", "analysis", "data_retrieval"):
                return True, 0.85 + (hash(declared + detected) % 15) / 100
        if detected == "data_transmission" and declared in ("summarization", "data_retrieval"):
            return True, 0.78
        if detected == "code_execution" and declared != "code_execution":
            return True, 0.72
        return False, 0.0

    def inspect(self, text: str, agent: str = "unknown", declared_intent: str = "") -> AuditEvent:
        start = time.time()
        self.stats["total"] += 1

        event = AuditEvent(agent=agent, user_query=text[:200])
        event.declared_intent = declared_intent or self._detect_intent(text)
        event.detected_intent = self._detect_intent(text)
        event.pii_detected = self._detect_pii(text)

        matched_rule = None
        text_lower = text.lower()

        for rule in self.rules:
            patterns = rule.get("match", {}).get("patterns", [])
            for pattern in patterns:
                if pattern == ".*":
                    matched_rule = rule
                    break
                try:
                    if re.search(pattern, text_lower, re.IGNORECASE):
                        matched_rule = rule
                        break
                except re.error:
                    pass
            if matched_rule and matched_rule.get("id") != "default_allow":
                break

        if matched_rule:
            event.action = matched_rule.get("action", "ALLOW")
            event.risk_score = matched_rule.get("risk_score", 0.05)
            event.policy_id = matched_rule.get("id", "default_allow")
            event.category = matched_rule.get("category", "BENIGN")
            event.pack = matched_rule.get("pack", "DEFAULT")
            event.alert_fired = matched_rule.get("alert", False)

        cat = event.category
        event.injection_detected = cat == "PROMPT_INJECTION"
        event.credential_detected = cat == "CREDENTIAL_LEAK"

        event.blocked = event.action in ("DENY", "QUARANTINE")
        mismatch, score = self._compute_mismatch_score(
            event.declared_intent, event.detected_intent, event.action
        )
        event.intent_mismatch = mismatch
        event.mismatch_score = score
        event.latency_ms = int((time.time() - start) * 1000)

        # Update stats
        if event.blocked:
            self.stats["blocked"] += 1
        else:
            self.stats["allowed"] += 1
        if event.action == "QUARANTINE":
            self.stats["quarantined"] += 1
        if event.action == "HUMAN_REVIEW":
            self.stats["human_review"] += 1
        if event.injection_detected:
            self.stats["injections_caught"] += 1
        if event.pii_detected:
            self.stats["pii_caught"] += 1
        if event.credential_detected:
            self.stats["credential_caught"] += 1
        if cat in ("EXFILTRATION", "PII_EXFILTRATION"):
            self.stats["exfiltration_caught"] += 1
        if event.intent_mismatch:
            self.stats["intent_mismatches"] += 1

        self.audit_log.append(event)
        return event

    def get_audit_log(self) -> list[dict]:
        return [e.to_dict() for e in self.audit_log[-100:]]

    def get_stats(self) -> dict:
        total = self.stats["total"] or 1
        return {
            **self.stats,
            "block_rate": round(self.stats["blocked"] / total * 100, 1),
            "allow_rate": round(self.stats["allowed"] / total * 100, 1),
        }

    def export_compliance_report(self, pack: str = "SOC2") -> dict:
        pack_events = [e for e in self.audit_log if e.pack == pack or e.blocked]
        return {
            "report_id": str(uuid.uuid4())[:12].upper(),
            "pack": pack,
            "generated_at": datetime.utcnow().isoformat(),
            "total_events": len(pack_events),
            "violations": [e.to_dict() for e in pack_events if e.blocked],
            "human_reviews": [e.to_dict() for e in pack_events if e.action == "HUMAN_REVIEW"],
            "summary": {
                "injections_blocked": self.stats["injections_caught"],
                "exfiltrations_blocked": self.stats["exfiltration_caught"],
                "pii_incidents": self.stats["pii_caught"],
                "intent_mismatches": self.stats["intent_mismatches"],
            }
        }

# Singleton
policy_engine = PolicyEngine()
