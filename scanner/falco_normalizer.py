"""
Falco Runtime Alert Normalizer for PostureLens.
Ingests raw Falco JSON alert payloads, normalizes priorities, and extracts structured
runtime violation metadata matching PostureLens standard violation schema.
"""

import hashlib
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

# Mapping Falco alert priorities to PostureLens severity levels
FALCO_PRIORITY_MAP = {
    "EMERGENCY": "critical",
    "ALERT": "critical",
    "CRITICAL": "critical",
    "ERROR": "high",
    "WARNING": "medium",
    "NOTICE": "low",
    "INFORMATIONAL": "low",
    "DEBUG": "low",
}


class NormalizedRuntimeAlert(BaseModel):
    """Normalized runtime security alert representation."""
    rule_id: str
    rule_name: str
    severity: str  # "critical" | "high" | "medium" | "low"
    title: str
    description: str
    field_path: str
    container_id: str = "N/A"
    pod_name: str = "N/A"
    namespace: str = "default"
    raw_payload: Dict[str, Any] = Field(default_factory=dict)


class FalcoAlertNormalizer:
    """Normalizes Falco alert payloads into PostureLens violation schema."""

    @staticmethod
    def normalize(payload: Dict[str, Any]) -> NormalizedRuntimeAlert:
        """
        Normalize a raw Falco JSON webhook alert payload.
        """
        rule_name = payload.get("rule", "Unknown Falco Rule")
        raw_priority = str(payload.get("priority", "NOTICE")).upper()
        output_text = payload.get("output", "")
        output_fields = payload.get("output_fields", {}) or {}

        # Map severity
        severity = FALCO_PRIORITY_MAP.get(raw_priority, "low")

        # Generate stable rule_id prefix e.g. FALCO-RUN-A1B2
        rule_hash = hashlib.md5(rule_name.encode("utf-8")).hexdigest()[:4].upper()
        rule_id = f"FALCO-RUN-{rule_hash}"

        # Extract container & k8s metadata from output_fields
        container_id = (
            output_fields.get("container.id") or
            output_fields.get("container_id") or
            "N/A"
        )
        if container_id != "N/A" and len(container_id) > 12:
            container_id = container_id[:12]

        pod_name = (
            output_fields.get("k8s.pod.name") or
            output_fields.get("pod_name") or
            output_fields.get("container.name") or
            "N/A"
        )

        namespace = (
            output_fields.get("k8s.ns.name") or
            output_fields.get("namespace") or
            "default"
        )

        # Construct target field path for UI tracing
        field_path = f"k8s.pod/{namespace}/{pod_name}"
        if container_id != "N/A":
            field_path += f"/container/{container_id}"

        title = f"Runtime Alert: {rule_name}"
        description = output_text if output_text else f"Falco detected runtime violation: {rule_name}"

        return NormalizedRuntimeAlert(
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            title=title,
            description=description,
            field_path=field_path,
            container_id=str(container_id),
            pod_name=str(pod_name),
            namespace=str(namespace),
            raw_payload=payload
        )
