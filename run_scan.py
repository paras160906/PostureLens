"""
Verification script to scan Task 1 fixture files using PostureLens scanner + OPA policies
and output structured JSON results.
"""

import json
from pathlib import Path
from scanner import (
    DockerfileAnalyzer,
    K8sManifestAnalyzer,
    OPAEngine,
)

FIXTURES_DIR = Path(__file__).parent / "tests" / "fixtures"


def scan_all():
    opa_engine = OPAEngine()
    results = {}

    # 1. Clean Dockerfile
    clean_df = FIXTURES_DIR / "dockerfiles" / "Dockerfile.clean"
    df_clean_parsed = DockerfileAnalyzer(file_path=str(clean_df)).analyze()
    results["Dockerfile.clean"] = opa_engine.evaluate_dockerfile(df_clean_parsed).model_dump()

    # 2. Misconfigured Dockerfile
    mis_df = FIXTURES_DIR / "dockerfiles" / "Dockerfile.misconfigured"
    df_mis_parsed = DockerfileAnalyzer(file_path=str(mis_df)).analyze()
    results["Dockerfile.misconfigured"] = opa_engine.evaluate_dockerfile(df_mis_parsed).model_dump()

    # 3. Clean K8s Pod
    clean_k8s = FIXTURES_DIR / "k8s" / "clean_pod.yaml"
    k8s_clean_parsed = K8sManifestAnalyzer(file_path=str(clean_k8s)).analyze()
    results["clean_pod.yaml"] = opa_engine.evaluate_k8s_manifest(k8s_clean_parsed).model_dump()

    # 4. Misconfigured K8s Pod
    mis_k8s = FIXTURES_DIR / "k8s" / "misconfigured_pod.yaml"
    k8s_mis_parsed = K8sManifestAnalyzer(file_path=str(mis_k8s)).analyze()
    results["misconfigured_pod.yaml"] = opa_engine.evaluate_k8s_manifest(k8s_mis_parsed).model_dump()

    # 5. RBAC Binding
    rbac_k8s = FIXTURES_DIR / "k8s" / "rbac_binding.yaml"
    rbac_parsed = K8sManifestAnalyzer(file_path=str(rbac_k8s)).analyze()
    results["rbac_binding.yaml"] = opa_engine.evaluate_k8s_manifest(rbac_parsed).model_dump()

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    scan_all()
