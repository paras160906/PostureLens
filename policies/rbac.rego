package posturelens

import rego.v1

# RBAC-001: ClusterRoleBinding to cluster-admin
violations contains {
    "rule_id": "RBAC-001",
    "severity": "critical",
    "title": "Binding Granted cluster-admin Privileges",
    "description": sprintf("RBAC binding '%s' grants full cluster-admin superuser role.", [b.name]),
    "field_path": sprintf("k8s.rbac_bindings[%d].role_ref", [bi])
} if {
    some bi
    b := input.k8s.rbac_bindings[bi]
    b.binds_cluster_admin == true
}

# RBAC-002: Binding to default ServiceAccount
violations contains {
    "rule_id": "RBAC-002",
    "severity": "high",
    "title": "Role Bound to Default ServiceAccount",
    "description": sprintf("RBAC binding '%s' binds permissions to the 'default' service account.", [b.name]),
    "field_path": sprintf("k8s.rbac_bindings[%d].subjects", [bi])
} if {
    some bi
    b := input.k8s.rbac_bindings[bi]
    b.binds_default_service_account == true
}
