"""
OPA Engine module for PostureLens.
Wraps Open Policy Agent (OPA) binary execution, feeds scanner metadata,
evaluates Rego policies, extracts violations, and computes weighted risk scores.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from pydantic import BaseModel, Field

from .dockerfile_parser import DockerfileScanResult
from .k8s_parser import K8sManifestScanResult


SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1
}


class Violation(BaseModel):
    """Structured security policy violation object."""
    rule_id: str
    severity: str  # "critical" | "high" | "medium" | "low"
    title: str
    description: str
    field_path: str


class RiskScore(BaseModel):
    """CVSS-inspired weighted risk score evaluation."""
    score: int = Field(ge=0, le=100)
    level: str  # "CLEAN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    breakdown: Dict[str, int] = Field(default_factory=dict)
    total_violations: int = 0


class PolicyScanReport(BaseModel):
    """Complete report combining policy violations and calculated risk score."""
    file_path: Optional[str] = None
    target_type: str = "combined"
    violations: List[Violation] = Field(default_factory=list)
    risk_score: RiskScore


class OPAEngine:
    """OPA Policy Evaluation Engine."""

    def __init__(
        self,
        policies_dir: Optional[Union[str, Path]] = None,
        opa_binary_path: Optional[Union[str, Path]] = None
    ):
        """
        Initialize the OPA Engine.
        Finds `opa` in PATH or checks `.bin/opa.exe` relative to project root.
        """
        project_root = Path(__file__).parent.parent
        self.policies_dir = Path(policies_dir) if policies_dir else project_root / "policies"
        
        if not self.policies_dir.exists():
            raise FileNotFoundError(f"Policies directory not found at {self.policies_dir}")

        self.opa_path = self._resolve_opa_binary(opa_binary_path, project_root)

    def _resolve_opa_binary(
        self,
        custom_path: Optional[Union[str, Path]],
        project_root: Path
    ) -> str:
        """Locate OPA executable binary."""
        if custom_path:
            p = Path(custom_path)
            if p.exists():
                return str(p)

        # Check system PATH
        system_opa = shutil.which("opa")
        if system_opa:
            return system_opa

        # Check local project .bin directory
        local_bin_exe = project_root / ".bin" / "opa.exe"
        if local_bin_exe.exists():
            return str(local_bin_exe)

        local_bin = project_root / ".bin" / "opa"
        if local_bin.exists():
            return str(local_bin)

        raise FileNotFoundError(
            "OPA binary not found. Please install OPA or place opa.exe in .bin/"
        )

    def evaluate_dockerfile(
        self,
        scan_result: DockerfileScanResult
    ) -> PolicyScanReport:
        """Evaluate a Dockerfile scan result against Rego policies."""
        input_data = {
            "dockerfile": scan_result.model_dump(),
            "k8s": {"pod_specs": [], "rbac_bindings": [], "kinds_found": []}
        }
        violations = self.run_opa_eval(input_data)
        risk_score = self.calculate_risk_score(violations)

        return PolicyScanReport(
            file_path=scan_result.file_path,
            target_type="dockerfile",
            violations=violations,
            risk_score=risk_score
        )

    def evaluate_k8s_manifest(
        self,
        scan_result: K8sManifestScanResult
    ) -> PolicyScanReport:
        """Evaluate a Kubernetes manifest scan result against Rego policies."""
        input_data = {
            "dockerfile": {
                "is_root_user": False,
                "base_images": [],
                "user_instructions": [],
                "exposed_ports": [],
                "env_vars": [],
                "copy_add_instructions": []
            },
            "k8s": scan_result.model_dump()
        }
        violations = self.run_opa_eval(input_data)
        risk_score = self.calculate_risk_score(violations)

        return PolicyScanReport(
            file_path=scan_result.file_path,
            target_type="k8s",
            violations=violations,
            risk_score=risk_score
        )

    def evaluate_combined(
        self,
        dockerfile_result: Optional[DockerfileScanResult] = None,
        k8s_result: Optional[K8sManifestScanResult] = None,
        file_path: Optional[str] = None
    ) -> PolicyScanReport:
        """Evaluate combined Dockerfile and Kubernetes scan results."""
        input_data: Dict[str, Any] = {
            "dockerfile": dockerfile_result.model_dump() if dockerfile_result else {
                "is_root_user": False,
                "base_images": [],
                "user_instructions": [],
                "exposed_ports": [],
                "env_vars": [],
                "copy_add_instructions": []
            },
            "k8s": k8s_result.model_dump() if k8s_result else {
                "pod_specs": [],
                "rbac_bindings": [],
                "kinds_found": []
            }
        }
        violations = self.run_opa_eval(input_data)
        risk_score = self.calculate_risk_score(violations)

        return PolicyScanReport(
            file_path=file_path,
            target_type="combined",
            violations=violations,
            risk_score=risk_score
        )

    def run_opa_eval(self, input_data: Dict[str, Any]) -> List[Violation]:
        """Execute `opa eval` via subprocess passing input JSON and collecting violations."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            json.dump(input_data, tmp)
            tmp_path = tmp.name

        try:
            cmd = [
                self.opa_path,
                "eval",
                "--data", str(self.policies_dir),
                "--input", tmp_path,
                "data.posturelens.violations",
                "--format", "json"
            ]

            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=True
            )

            return self._parse_opa_output(res.stdout)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"OPA evaluation failed: {e.stderr or e.stdout}")
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def _parse_opa_output(self, raw_json: str) -> List[Violation]:
        """Extract structured Violation objects from OPA JSON stdout."""
        data = json.loads(raw_json)
        violations: List[Violation] = []

        results = data.get("result", [])
        for res in results:
            expressions = res.get("expressions", [])
            for expr in expressions:
                val = expr.get("value")
                if isinstance(val, list):
                    for v in val:
                        if isinstance(v, dict):
                            violations.append(
                                Violation(
                                    rule_id=v.get("rule_id", "UNKNOWN"),
                                    severity=v.get("severity", "low").lower(),
                                    title=v.get("title", "Policy Violation"),
                                    description=v.get("description", ""),
                                    field_path=v.get("field_path", "")
                                )
                            )

        # Sort violations by severity weight descending
        violations.sort(
            key=lambda v: SEVERITY_WEIGHTS.get(v.severity, 0),
            reverse=True
        )
        return violations

    @staticmethod
    def calculate_risk_score(violations: List[Violation]) -> RiskScore:
        """
        Calculate CVSS-inspired weighted risk score capped at 100.
        Weights: critical=10, high=7, medium=4, low=1.
        """
        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total_points = 0

        for v in violations:
            sev = v.severity.lower()
            if sev in breakdown:
                breakdown[sev] += 1
            weight = SEVERITY_WEIGHTS.get(sev, 1)
            total_points += weight

        final_score = min(total_points, 100)

        # Assign risk level based on final score
        if final_score == 0:
            level = "CLEAN"
        elif final_score <= 20:
            level = "LOW"
        elif final_score <= 50:
            level = "MEDIUM"
        elif final_score <= 80:
            level = "HIGH"
        else:
            level = "CRITICAL"

        return RiskScore(
            score=final_score,
            level=level,
            breakdown=breakdown,
            total_violations=len(violations)
        )
