"""
Kubernetes Manifest Parser module for PostureLens Security Posture Tool.
Uses PyYAML to extract security-relevant fields from single or multi-doc K8s manifests.
"""

from typing import List, Dict, Any, Optional, Union
from pathlib import Path
from pydantic import BaseModel, Field
import yaml


class CapabilitiesSpec(BaseModel):
    """Container capability additions and drops."""
    add: List[str] = Field(default_factory=list)
    drop: List[str] = Field(default_factory=list)


class SecurityContextSpec(BaseModel):
    """Detailed security context fields for pods and containers."""
    runAsNonRoot: Optional[bool] = None
    runAsUser: Optional[int] = None
    runAsGroup: Optional[int] = None
    readOnlyRootFilesystem: Optional[bool] = None
    allowPrivilegeEscalation: Optional[bool] = None
    privileged: Optional[bool] = None
    capabilities: CapabilitiesSpec = Field(default_factory=CapabilitiesSpec)
    seccompProfile: Optional[Dict[str, Any]] = None


class ResourceLimitsSpec(BaseModel):
    """Resource limits and requests for containers."""
    limits: Dict[str, str] = Field(default_factory=dict)
    requests: Dict[str, str] = Field(default_factory=dict)
    has_cpu_limit: bool = False
    has_memory_limit: bool = False


class ContainerSecuritySpec(BaseModel):
    """Security assessment for individual containers inside a Pod."""
    name: str
    image: str
    security_context: SecurityContextSpec = Field(default_factory=SecurityContextSpec)
    resources: ResourceLimitsSpec = Field(default_factory=ResourceLimitsSpec)
    is_privileged: bool = False
    allows_privilege_escalation: bool = True  # Default in K8s if not specified
    read_only_root_fs: bool = False
    runs_as_non_root: Optional[bool] = None


class PodSecuritySpec(BaseModel):
    """Security specification extracted from a Pod or Workload PodTemplate."""
    pod_name: str
    workload_kind: str
    namespace: Optional[str] = None
    pod_security_context: SecurityContextSpec = Field(default_factory=SecurityContextSpec)
    host_network: bool = False
    host_pid: bool = False
    host_ipc: bool = False
    containers: List[ContainerSecuritySpec] = Field(default_factory=list)
    init_containers: List[ContainerSecuritySpec] = Field(default_factory=list)
    service_account_name: Optional[str] = None
    automount_service_account_token: Optional[bool] = None


class RBACSubjectSpec(BaseModel):
    """Subject details in RoleBinding / ClusterRoleBinding."""
    kind: str
    name: str
    namespace: Optional[str] = None


class RBACRoleRefSpec(BaseModel):
    """Role reference in RoleBinding / ClusterRoleBinding."""
    kind: str
    name: str
    apiGroup: str = "rbac.authorization.k8s.io"


class RBACBindingSpec(BaseModel):
    """Security spec for RBAC RoleBindings and ClusterRoleBindings."""
    name: str
    kind: str  # RoleBinding or ClusterRoleBinding
    namespace: Optional[str] = None
    role_ref: RBACRoleRefSpec
    subjects: List[RBACSubjectSpec] = Field(default_factory=list)
    binds_cluster_admin: bool = False
    binds_default_service_account: bool = False


class K8sManifestScanResult(BaseModel):
    """Complete scan results for a Kubernetes manifest file or YAML content."""
    file_path: Optional[str] = None
    pod_specs: List[PodSecuritySpec] = Field(default_factory=list)
    rbac_bindings: List[RBACBindingSpec] = Field(default_factory=list)
    total_documents: int = 0
    kinds_found: List[str] = Field(default_factory=list)


class K8sManifestAnalyzer:
    """Analyzer class for parsing Kubernetes YAML manifests."""

    WORKLOAD_KINDS = {
        "Pod", "Deployment", "DaemonSet", "StatefulSet",
        "ReplicaSet", "Job", "CronJob"
    }

    def __init__(self, file_path: Optional[str] = None, content: Optional[str] = None):
        """Initialize with file path or raw YAML string."""
        if file_path is None and content is None:
            raise ValueError("Either file_path or content must be provided.")

        self.file_path = file_path
        if file_path:
            path_obj = Path(file_path)
            if not path_obj.exists():
                raise FileNotFoundError(f"Kubernetes manifest not found at {file_path}")
            self.raw_yaml = path_obj.read_text(encoding="utf-8")
        else:
            self.raw_yaml = content or ""

    def analyze(self) -> K8sManifestScanResult:
        """Parse single or multi-document YAML and extract security specs."""
        docs = list(yaml.safe_load_all(self.raw_yaml))

        pod_specs: List[PodSecuritySpec] = []
        rbac_bindings: List[RBACBindingSpec] = []
        kinds_found: List[str] = []
        valid_doc_count = 0

        for doc in docs:
            if not doc or not isinstance(doc, dict):
                continue
            
            valid_doc_count += 1
            kind = doc.get("kind", "")
            if kind:
                kinds_found.append(kind)

            # Check if workload resource containing Pod spec
            if kind in self.WORKLOAD_KINDS:
                extracted_pod = self._extract_pod_spec(doc)
                if extracted_pod:
                    pod_specs.append(extracted_pod)

            # Check if RBAC Binding
            elif kind in ("RoleBinding", "ClusterRoleBinding"):
                extracted_rbac = self._extract_rbac_binding(doc)
                if extracted_rbac:
                    rbac_bindings.append(extracted_rbac)

        return K8sManifestScanResult(
            file_path=self.file_path,
            pod_specs=pod_specs,
            rbac_bindings=rbac_bindings,
            total_documents=valid_doc_count,
            kinds_found=kinds_found
        )

    def _extract_pod_spec(self, doc: Dict[str, Any]) -> Optional[PodSecuritySpec]:
        """Navigate manifest structure to extract PodSpec and PodTemplateSpec."""
        metadata = doc.get("metadata", {})
        resource_name = metadata.get("name", "unnamed")
        namespace = metadata.get("namespace", "default")
        kind = doc.get("kind", "Pod")

        # Find pod spec dict depending on resource kind
        if kind == "Pod":
            pod_spec_dict = doc.get("spec", {})
        elif kind == "CronJob":
            pod_spec_dict = (
                doc.get("spec", {})
                .get("jobTemplate", {})
                .get("spec", {})
                .get("template", {})
                .get("spec", {})
            )
        else:
            # Deployment, DaemonSet, StatefulSet, ReplicaSet, Job
            pod_spec_dict = doc.get("spec", {}).get("template", {}).get("spec", {})

        if not pod_spec_dict:
            return None

        # Extract Pod-level flags and security context
        host_net = pod_spec_dict.get("hostNetwork", False)
        host_pid = pod_spec_dict.get("hostPID", False)
        host_ipc = pod_spec_dict.get("hostIPC", False)
        sa_name = pod_spec_dict.get("serviceAccountName") or pod_spec_dict.get("serviceAccount")
        automount_sa = pod_spec_dict.get("automountServiceAccountToken")

        pod_sec_ctx_dict = pod_spec_dict.get("securityContext", {})
        pod_sec_ctx = self._parse_security_context(pod_sec_ctx_dict)

        # Extract Containers
        containers_raw = pod_spec_dict.get("containers", [])
        init_containers_raw = pod_spec_dict.get("initContainers", [])

        containers = [self._parse_container_spec(c, pod_sec_ctx) for c in containers_raw]
        init_containers = [self._parse_container_spec(c, pod_sec_ctx) for c in init_containers_raw]

        return PodSecuritySpec(
            pod_name=resource_name,
            workload_kind=kind,
            namespace=namespace,
            pod_security_context=pod_sec_ctx,
            host_network=host_net,
            host_pid=host_pid,
            host_ipc=host_ipc,
            containers=containers,
            init_containers=init_containers,
            service_account_name=sa_name,
            automount_service_account_token=automount_sa
        )

    def _parse_container_spec(
        self,
        c_dict: Dict[str, Any],
        pod_sec_ctx: SecurityContextSpec
    ) -> ContainerSecuritySpec:
        """Parse individual container spec including securityContext and resource limits."""
        c_name = c_dict.get("name", "unnamed")
        c_image = c_dict.get("image", "")

        c_sec_ctx_dict = c_dict.get("securityContext", {})
        c_sec_ctx = self._parse_security_context(c_sec_ctx_dict)

        # Privilege & Root flags
        is_privileged = bool(c_sec_ctx.privileged)
        
        # Effective allowPrivilegeEscalation: container level setting or default (true if privileged or not set)
        if c_sec_ctx.allowPrivilegeEscalation is not None:
            allow_esc = c_sec_ctx.allowPrivilegeEscalation
        else:
            allow_esc = is_privileged or True

        read_only_root = bool(c_sec_ctx.readOnlyRootFilesystem)

        # Effective runAsNonRoot: container level takes priority over pod level
        runs_non_root = c_sec_ctx.runAsNonRoot
        if runs_non_root is None:
            runs_non_root = pod_sec_ctx.runAsNonRoot

        # Resources limits & requests
        res_dict = c_dict.get("resources", {})
        limits = res_dict.get("limits", {}) or {}
        requests = res_dict.get("requests", {}) or {}

        has_cpu_lim = "cpu" in limits
        has_mem_lim = "memory" in limits

        res_spec = ResourceLimitsSpec(
            limits={k: str(v) for k, v in limits.items()},
            requests={k: str(v) for k, v in requests.items()},
            has_cpu_limit=has_cpu_lim,
            has_memory_limit=has_mem_lim
        )

        return ContainerSecuritySpec(
            name=c_name,
            image=c_image,
            security_context=c_sec_ctx,
            resources=res_spec,
            is_privileged=is_privileged,
            allows_privilege_escalation=allow_esc,
            read_only_root_fs=read_only_root,
            runs_as_non_root=runs_non_root
        )

    def _parse_security_context(self, sec_dict: Dict[str, Any]) -> SecurityContextSpec:
        """Parse a securityContext dictionary into SecurityContextSpec model."""
        if not sec_dict or not isinstance(sec_dict, dict):
            return SecurityContextSpec()

        cap_dict = sec_dict.get("capabilities", {})
        cap_add = cap_dict.get("add", []) if isinstance(cap_dict, dict) else []
        cap_drop = cap_dict.get("drop", []) if isinstance(cap_dict, dict) else []

        capabilities = CapabilitiesSpec(add=cap_add, drop=cap_drop)

        return SecurityContextSpec(
            runAsNonRoot=sec_dict.get("runAsNonRoot"),
            runAsUser=sec_dict.get("runAsUser"),
            runAsGroup=sec_dict.get("runAsGroup"),
            readOnlyRootFilesystem=sec_dict.get("readOnlyRootFilesystem"),
            allowPrivilegeEscalation=sec_dict.get("allowPrivilegeEscalation"),
            privileged=sec_dict.get("privileged"),
            capabilities=capabilities,
            seccompProfile=sec_dict.get("seccompProfile")
        )

    def _extract_rbac_binding(self, doc: Dict[str, Any]) -> RBACBindingSpec:
        """Extract RBAC RoleBinding / ClusterRoleBinding details."""
        metadata = doc.get("metadata", {})
        binding_name = metadata.get("name", "unnamed")
        namespace = metadata.get("namespace")
        kind = doc.get("kind", "RoleBinding")

        role_ref_dict = doc.get("roleRef", {})
        role_ref = RBACRoleRefSpec(
            kind=role_ref_dict.get("kind", "Role"),
            name=role_ref_dict.get("name", ""),
            apiGroup=role_ref_dict.get("apiGroup", "rbac.authorization.k8s.io")
        )

        subjects_raw = doc.get("subjects", [])
        subjects = []
        binds_default_sa = False

        for sub in subjects_raw:
            sub_kind = sub.get("kind", "")
            sub_name = sub.get("name", "")
            sub_ns = sub.get("namespace")
            subjects.append(
                RBACSubjectSpec(kind=sub_kind, name=sub_name, namespace=sub_ns)
            )
            if sub_kind == "ServiceAccount" and sub_name == "default":
                binds_default_sa = True

        binds_admin = (role_ref.name == "cluster-admin")

        return RBACBindingSpec(
            name=binding_name,
            kind=kind,
            namespace=namespace,
            role_ref=role_ref,
            subjects=subjects,
            binds_cluster_admin=binds_admin,
            binds_default_service_account=binds_default_sa
        )
