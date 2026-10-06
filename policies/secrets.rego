package posturelens

import rego.v1

# SECRETS-001: Sensitive ENV variable in Dockerfile
violations contains {
    "rule_id": "SECRETS-001",
    "severity": "critical",
    "title": "Potentially Sensitive Credential in ENV Variable",
    "description": sprintf("Dockerfile defines ENV variable '%s' which appears to contain sensitive secret data.", [env.key]),
    "field_path": sprintf("dockerfile.env_vars[%d]", [i])
} if {
    some i
    env := input.dockerfile.env_vars[i]
    env.is_potentially_sensitive == true
}

# SECRETS-002: ADD instruction used in Dockerfile
violations contains {
    "rule_id": "SECRETS-002",
    "severity": "high",
    "title": "Insecure ADD Instruction Used",
    "description": sprintf("Dockerfile uses ADD instruction ('%s'). Prefer COPY for local files to avoid remote URL fetching or unexpected tar auto-extraction.", [inst.source]),
    "field_path": sprintf("dockerfile.copy_add_instructions[%d]", [i])
} if {
    some i
    inst := input.dockerfile.copy_add_instructions[i]
    inst.is_add == true
}
