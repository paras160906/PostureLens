"""
Policy Registry for PostureLens.
Extracts metadata from loaded Rego policy files for API discovery.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
from pydantic import BaseModel


class PolicyRuleMetadata(BaseModel):
    """Metadata representation of an OPA Rego policy rule."""
    id: str
    category: str
    severity: str
    title: str
    description: str


# Static catalog of all Rego policy rules implemented in /policies
POLICY_CATALOG: List[PolicyRuleMetadata] = [
    # Container Category
    PolicyRuleMetadata(
        id="CONTAINER-001",
        category="container",
        severity="high",
        title="Dockerfile Runs As Root User",
        description="The Dockerfile does not specify a non-root USER instruction or explicitly runs as root."
    ),
    PolicyRuleMetadata(
        id="CONTAINER-002",
        category="container",
        severity="medium",
        title="Unpinned or Latest Base Image Tag",
        description="Base image uses the latest or an unpinned tag instead of a explicit version pin."
    ),
    PolicyRuleMetadata(
        id="CONTAINER-003",
        category="container",
        severity="critical",
        title="Privileged Container Execution",
        description="Container runs in privileged mode, granting full capabilities of the host system."
    ),
    PolicyRuleMetadata(
        id="CONTAINER-004",
        category="container",
        severity="high",
        title="Privilege Escalation Allowed",
        description="Container allows privilege escalation via setuid/setgid binaries."
    ),

    # Resources Category
    PolicyRuleMetadata(
        id="RESOURCES-001",
        category="resources",
        severity="medium",
        title="Missing CPU Resource Limit",
        description="Container spec does not specify a CPU limit, risking CPU starvation on the node."
    ),
    PolicyRuleMetadata(
        id="RESOURCES-002",
        category="resources",
        severity="medium",
        title="Missing Memory Resource Limit",
        description="Container spec does not specify a Memory limit, risking OOM kills of adjacent containers."
    ),

    # Network Category
    PolicyRuleMetadata(
        id="NETWORK-001",
        category="network",
        severity="high",
        title="Host Network Namespace Shared",
        description="Pod shares the host network namespace (hostNetwork=true), exposing host network interfaces."
    ),
    PolicyRuleMetadata(
        id="NETWORK-002",
        category="network",
        severity="high",
        title="Host PID Namespace Shared",
        description="Pod shares the host PID namespace (hostPID=true), exposing processes running on the node."
    ),
    PolicyRuleMetadata(
        id="NETWORK-003",
        category="network",
        severity="high",
        title="Host IPC Namespace Shared",
        description="Pod shares the host IPC namespace (hostIPC=true), allowing inter-process communication with host processes."
    ),
    PolicyRuleMetadata(
        id="NETWORK-004",
        category="network",
        severity="medium",
        title="SSH Port Exposed In Dockerfile",
        description="Dockerfile exposes port 22 (SSH). SSH should not run inside application containers."
    ),
    PolicyRuleMetadata(
        id="NETWORK-005",
        category="network",
        severity="low",
        title="Missing NetworkPolicy Resource",
        description="Manifest contains workloads but no NetworkPolicy is defined to isolate ingress/egress network traffic."
    ),

    # Secrets Category
    PolicyRuleMetadata(
        id="SECRETS-001",
        category="secrets",
        severity="critical",
        title="Potentially Sensitive Credential in ENV Variable",
        description="Dockerfile defines environment variables containing sensitive credential or secret keywords."
    ),
    PolicyRuleMetadata(
        id="SECRETS-002",
        category="secrets",
        severity="high",
        title="Insecure ADD Instruction Used",
        description="Dockerfile uses ADD instead of COPY, risking unintended tar auto-extraction or remote URL downloads."
    ),

    # RBAC Category
    PolicyRuleMetadata(
        id="RBAC-001",
        category="rbac",
        severity="critical",
        title="Binding Granted cluster-admin Privileges",
        description="RBAC RoleBinding/ClusterRoleBinding grants full superuser cluster-admin access."
    ),
    PolicyRuleMetadata(
        id="RBAC-002",
        category="rbac",
        severity="high",
        title="Role Bound to Default ServiceAccount",
        description="RBAC binding grants permissions to the 'default' service account instead of a dedicated service account."
    ),
]


def list_loaded_policies() -> List[PolicyRuleMetadata]:
    """Return catalog of loaded Rego policy rules with metadata."""
    return POLICY_CATALOG
