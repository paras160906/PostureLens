"""
Unit tests for Kubernetes Manifest parser module.
"""

import pytest
from pathlib import Path
from scanner.k8s_parser import K8sManifestAnalyzer, K8sManifestScanResult

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "k8s"


def test_clean_k8s_manifest():
    """Test parsing a secure Deployment manifest."""
    clean_path = FIXTURES_DIR / "clean_pod.yaml"
    analyzer = K8sManifestAnalyzer(file_path=str(clean_path))
    result: K8sManifestScanResult = analyzer.analyze()

    assert result.total_documents == 1
    assert "Deployment" in result.kinds_found
    assert len(result.pod_specs) == 1

    pod_spec = result.pod_specs[0]
    assert pod_spec.pod_name == "secure-web-app"
    assert pod_spec.workload_kind == "Deployment"
    assert pod_spec.namespace == "prod"

    # Host isolation checks
    assert pod_spec.host_network is False
    assert pod_spec.host_pid is False
    assert pod_spec.host_ipc is False
    assert pod_spec.automount_service_account_token is False

    # Pod level securityContext
    assert pod_spec.pod_security_context.runAsNonRoot is True
    assert pod_spec.pod_security_context.runAsUser == 10001

    # Container level checks
    assert len(pod_spec.containers) == 1
    c = pod_spec.containers[0]
    assert c.name == "web-container"
    assert c.image == "nginx:1.25.3-alpine"
    assert c.is_privileged is False
    assert c.allows_privilege_escalation is False
    assert c.read_only_root_fs is True
    assert c.runs_as_non_root is True
    assert "ALL" in c.security_context.capabilities.drop

    # Resource limit checks
    assert c.resources.has_cpu_limit is True
    assert c.resources.has_memory_limit is True
    assert c.resources.limits["cpu"] == "500m"
    assert c.resources.limits["memory"] == "512Mi"


def test_misconfigured_k8s_manifest():
    """Test parsing an insecure Pod manifest."""
    misconfigured_path = FIXTURES_DIR / "misconfigured_pod.yaml"
    analyzer = K8sManifestAnalyzer(file_path=str(misconfigured_path))
    result: K8sManifestScanResult = analyzer.analyze()

    assert len(result.pod_specs) == 1
    pod_spec = result.pod_specs[0]

    # Host namespace violation checks
    assert pod_spec.host_network is True
    assert pod_spec.host_pid is True
    assert pod_spec.host_ipc is True

    # Privileged container checks
    c = pod_spec.containers[0]
    assert c.is_privileged is True
    assert c.allows_privilege_escalation is True
    assert c.read_only_root_fs is False
    assert "SYS_ADMIN" in c.security_context.capabilities.add
    assert "ALL" in c.security_context.capabilities.add

    # Missing resource limits check
    assert c.resources.has_cpu_limit is False
    assert c.resources.has_memory_limit is False
    assert c.resources.limits == {}


def test_rbac_binding_manifest():
    """Test parsing RBAC RoleBinding and ClusterRoleBinding documents."""
    rbac_path = FIXTURES_DIR / "rbac_binding.yaml"
    analyzer = K8sManifestAnalyzer(file_path=str(rbac_path))
    result: K8sManifestScanResult = analyzer.analyze()

    assert result.total_documents == 2
    assert len(result.rbac_bindings) == 2

    # First binding: clean RoleBinding
    rb1 = result.rbac_bindings[0]
    assert rb1.kind == "RoleBinding"
    assert rb1.name == "read-pods-binding"
    assert rb1.role_ref.name == "pod-reader"
    assert rb1.binds_cluster_admin is False
    assert rb1.binds_default_service_account is False

    # Second binding: dangerous ClusterRoleBinding to default service account
    rb2 = result.rbac_bindings[1]
    assert rb2.kind == "ClusterRoleBinding"
    assert rb2.name == "dangerous-admin-binding"
    assert rb2.role_ref.name == "cluster-admin"
    assert rb2.binds_cluster_admin is True
    assert rb2.binds_default_service_account is True


def test_k8s_manifest_from_string_content():
    """Test parsing raw Kubernetes YAML string content."""
    content = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: inline-test-pod
    spec:
      containers:
        - name: busybox
          image: busybox:1.36
    """
    analyzer = K8sManifestAnalyzer(content=content)
    result = analyzer.analyze()

    assert result.total_documents == 1
    assert len(result.pod_specs) == 1
    assert result.pod_specs[0].pod_name == "inline-test-pod"


def test_missing_file_raises_error():
    """Test non-existent file path raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        K8sManifestAnalyzer(file_path="non_existent_k8s.yaml")


def test_empty_arguments_raises_error():
    """Test initializing without arguments raises ValueError."""
    with pytest.raises(ValueError):
        K8sManifestAnalyzer()
