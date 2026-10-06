package posturelens

import rego.v1

# RESOURCES-001: Missing CPU limit in container
violations contains {
    "rule_id": "RESOURCES-001",
    "severity": "medium",
    "title": "Missing CPU Resource Limit",
    "description": sprintf("Container '%s' in pod/workload '%s' does not specify a CPU limit.", [c.name, pod.pod_name]),
    "field_path": sprintf("k8s.pod_specs[%d].containers[%d].resources.limits.cpu", [pi, ci])
} if {
    some pi, ci
    pod := input.k8s.pod_specs[pi]
    c := pod.containers[ci]
    c.resources.has_cpu_limit == false
}

# RESOURCES-002: Missing Memory limit in container
violations contains {
    "rule_id": "RESOURCES-002",
    "severity": "medium",
    "title": "Missing Memory Resource Limit",
    "description": sprintf("Container '%s' in pod/workload '%s' does not specify a Memory limit.", [c.name, pod.pod_name]),
    "field_path": sprintf("k8s.pod_specs[%d].containers[%d].resources.limits.memory", [pi, ci])
} if {
    some pi, ci
    pod := input.k8s.pod_specs[pi]
    c := pod.containers[ci]
    c.resources.has_memory_limit == false
}
