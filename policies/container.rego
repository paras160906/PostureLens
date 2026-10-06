package posturelens

import rego.v1

# CONTAINER-001: Dockerfile runs as root
violations contains {
    "rule_id": "CONTAINER-001",
    "severity": "high",
    "title": "Dockerfile Runs As Root User",
    "description": "The Dockerfile does not specify a non-root USER instruction or explicitly runs as root.",
    "field_path": "dockerfile.user_instructions"
} if {
    input.dockerfile.is_root_user == true
}

# CONTAINER-002: Base image uses latest or unpinned tag
violations contains {
    "rule_id": "CONTAINER-002",
    "severity": "medium",
    "title": "Unpinned or Latest Base Image Tag",
    "description": sprintf("Base image '%s' uses the latest or an unpinned tag.", [img.image]),
    "field_path": sprintf("dockerfile.base_images[%d]", [i])
} if {
    some i
    img := input.dockerfile.base_images[i]
    img.is_latest_tag == true
}

# CONTAINER-003: Privileged container in K8s manifest
violations contains {
    "rule_id": "CONTAINER-003",
    "severity": "critical",
    "title": "Privileged Container Execution",
    "description": sprintf("Container '%s' in pod/workload '%s' has privileged=true.", [c.name, pod.pod_name]),
    "field_path": sprintf("k8s.pod_specs[%d].containers[%d].security_context.privileged", [pi, ci])
} if {
    some pi, ci
    pod := input.k8s.pod_specs[pi]
    c := pod.containers[ci]
    c.is_privileged == true
}

# CONTAINER-004: Allow privilege escalation in K8s container
violations contains {
    "rule_id": "CONTAINER-004",
    "severity": "high",
    "title": "Privilege Escalation Allowed",
    "description": sprintf("Container '%s' in pod/workload '%s' allows privilege escalation.", [c.name, pod.pod_name]),
    "field_path": sprintf("k8s.pod_specs[%d].containers[%d].security_context.allowPrivilegeEscalation", [pi, ci])
} if {
    some pi, ci
    pod := input.k8s.pod_specs[pi]
    c := pod.containers[ci]
    c.allows_privilege_escalation == true
    c.is_privileged == false
}
