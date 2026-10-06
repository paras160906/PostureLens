package posturelens

import rego.v1

# NETWORK-001: hostNetwork enabled
violations contains {
    "rule_id": "NETWORK-001",
    "severity": "high",
    "title": "Host Network Namespace Shared",
    "description": sprintf("Pod/workload '%s' has hostNetwork=true.", [pod.pod_name]),
    "field_path": sprintf("k8s.pod_specs[%d].host_network", [pi])
} if {
    some pi
    pod := input.k8s.pod_specs[pi]
    pod.host_network == true
}

# NETWORK-002: hostPID enabled
violations contains {
    "rule_id": "NETWORK-002",
    "severity": "high",
    "title": "Host PID Namespace Shared",
    "description": sprintf("Pod/workload '%s' has hostPID=true.", [pod.pod_name]),
    "field_path": sprintf("k8s.pod_specs[%d].host_pid", [pi])
} if {
    some pi
    pod := input.k8s.pod_specs[pi]
    pod.host_pid == true
}

# NETWORK-003: hostIPC enabled
violations contains {
    "rule_id": "NETWORK-003",
    "severity": "high",
    "title": "Host IPC Namespace Shared",
    "description": sprintf("Pod/workload '%s' has hostIPC=true.", [pod.pod_name]),
    "field_path": sprintf("k8s.pod_specs[%d].host_ipc", [pi])
} if {
    some pi
    pod := input.k8s.pod_specs[pi]
    pod.host_ipc == true
}

# NETWORK-004: Sensitive SSH Port exposed in Dockerfile
violations contains {
    "rule_id": "NETWORK-004",
    "severity": "medium",
    "title": "SSH Port Exposed In Dockerfile",
    "description": "Dockerfile exposes port 22 (SSH). SSH should not be run inside application containers.",
    "field_path": sprintf("dockerfile.exposed_ports[%d]", [i])
} if {
    some i
    port_info := input.dockerfile.exposed_ports[i]
    port_info.port == "22"
}

# NETWORK-005: Missing NetworkPolicy in K8s manifest set
violations contains {
    "rule_id": "NETWORK-005",
    "severity": "low",
    "title": "Missing NetworkPolicy Resource",
    "description": "Manifest contains workload resources but no NetworkPolicy is defined to restrict ingress/egress traffic.",
    "field_path": "k8s.kinds_found"
} if {
    count(input.k8s.pod_specs) > 0
    not netpolicy_found(input.k8s.kinds_found)
}

netpolicy_found(kinds) if {
    some k
    kinds[k] == "NetworkPolicy"
}
