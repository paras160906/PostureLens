"""
Unit tests for OPA Engine module and Rego policies.
"""

from pathlib import Path
from scanner import (
    DockerfileAnalyzer,
    K8sManifestAnalyzer,
    OPAEngine,
    Violation,
    RiskScore,
)

DOCKER_FIXTURES = Path(__file__).parent / "fixtures" / "dockerfiles"
K8S_FIXTURES = Path(__file__).parent / "fixtures" / "k8s"


def test_clean_dockerfile_opa():
    """Test clean Dockerfile fixture produces 0 violations and CLEAN risk level."""
    clean_path = DOCKER_FIXTURES / "Dockerfile.clean"
    parsed = DockerfileAnalyzer(file_path=str(clean_path)).analyze()

    engine = OPAEngine()
    report = engine.evaluate_dockerfile(parsed)

    assert report.risk_score.score == 0
    assert report.risk_score.level == "CLEAN"
    assert len(report.violations) == 0


def test_misconfigured_dockerfile_opa():
    """Test misconfigured Dockerfile fixture flags expected violations."""
    mis_path = DOCKER_FIXTURES / "Dockerfile.misconfigured"
    parsed = DockerfileAnalyzer(file_path=str(mis_path)).analyze()

    engine = OPAEngine()
    report = engine.evaluate_dockerfile(parsed)

    rule_ids = [v.rule_id for v in report.violations]
    assert "CONTAINER-001" in rule_ids  # root user
    assert "CONTAINER-002" in rule_ids  # latest tag
    assert "NETWORK-004" in rule_ids    # SSH port 22
    assert "SECRETS-001" in rule_ids    # AWS secret ENV
    assert "SECRETS-002" in rule_ids    # ADD instruction

    assert report.risk_score.score > 0
    assert report.risk_score.level in ("MEDIUM", "HIGH", "CRITICAL")


def test_clean_k8s_manifest_opa():
    """Test clean Kubernetes Deployment fixture has no critical/high violations."""
    clean_path = K8S_FIXTURES / "clean_pod.yaml"
    parsed = K8sManifestAnalyzer(file_path=str(clean_path)).analyze()

    engine = OPAEngine()
    report = engine.evaluate_k8s_manifest(parsed)

    crit_or_high = [
        v for v in report.violations if v.severity in ("critical", "high")
    ]
    assert len(crit_or_high) == 0


def test_misconfigured_k8s_manifest_opa():
    """Test misconfigured K8s Pod fixture flags privilege, host namespaces & resource limits."""
    mis_path = K8S_FIXTURES / "misconfigured_pod.yaml"
    parsed = K8sManifestAnalyzer(file_path=str(mis_path)).analyze()

    engine = OPAEngine()
    report = engine.evaluate_k8s_manifest(parsed)

    rule_ids = [v.rule_id for v in report.violations]
    assert "CONTAINER-003" in rule_ids  # privileged: true
    assert "NETWORK-001" in rule_ids    # hostNetwork
    assert "NETWORK-002" in rule_ids    # hostPID
    assert "NETWORK-003" in rule_ids    # hostIPC
    assert "RESOURCES-001" in rule_ids  # missing CPU limit
    assert "RESOURCES-002" in rule_ids  # missing Memory limit

    assert report.risk_score.score >= 30


def test_rbac_binding_opa():
    """Test RBAC binding fixture flags cluster-admin and default SA bindings."""
    rbac_path = K8S_FIXTURES / "rbac_binding.yaml"
    parsed = K8sManifestAnalyzer(file_path=str(rbac_path)).analyze()

    engine = OPAEngine()
    report = engine.evaluate_k8s_manifest(parsed)

    rule_ids = [v.rule_id for v in report.violations]
    assert "RBAC-001" in rule_ids  # cluster-admin binding
    assert "RBAC-002" in rule_ids  # default service account binding


def test_risk_score_calculation_capping():
    """Test risk score weighting and capping at 100."""
    # Create 12 critical violations (12 * 10 = 120 points -> capped at 100)
    violations = [
        Violation(
            rule_id=f"TEST-{i}",
            severity="critical",
            title="Critical Bug",
            description="Desc",
            field_path="path"
        )
        for i in range(12)
    ]
    score = OPAEngine.calculate_risk_score(violations)
    assert score.score == 100
    assert score.level == "CRITICAL"
    assert score.breakdown["critical"] == 12
