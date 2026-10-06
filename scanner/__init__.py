"""
PostureLens Scanner Package.
Core scan engines for container Dockerfiles and Kubernetes manifests,
integrated with Open Policy Agent (OPA) Rego policy engine and Falco runtime monitoring.
"""

from .dockerfile_parser import (
    DockerfileAnalyzer,
    DockerfileScanResult,
    BaseImageInfo,
    CopyAddInstruction,
    ExposedPortInfo,
    EnvVarInfo,
)
from .k8s_parser import (
    K8sManifestAnalyzer,
    K8sManifestScanResult,
    PodSecuritySpec,
    ContainerSecuritySpec,
    SecurityContextSpec,
    RBACBindingSpec,
    ResourceLimitsSpec,
)
from .opa_engine import (
    OPAEngine,
    Violation,
    RiskScore,
    PolicyScanReport,
)
from .falco_normalizer import (
    FalcoAlertNormalizer,
    NormalizedRuntimeAlert,
)
from .sbom_vulnerability import (
    SBOMEngine,
    OSVCorrelator,
)

__all__ = [
    "DockerfileAnalyzer",
    "DockerfileScanResult",
    "BaseImageInfo",
    "CopyAddInstruction",
    "ExposedPortInfo",
    "EnvVarInfo",
    "K8sManifestAnalyzer",
    "K8sManifestScanResult",
    "PodSecuritySpec",
    "ContainerSecuritySpec",
    "SecurityContextSpec",
    "RBACBindingSpec",
    "ResourceLimitsSpec",
    "OPAEngine",
    "Violation",
    "RiskScore",
    "PolicyScanReport",
    "FalcoAlertNormalizer",
    "NormalizedRuntimeAlert",
    "SBOMEngine",
    "OSVCorrelator",
]
