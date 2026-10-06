"""
Integration tests for PostureLens FastAPI backend endpoints.
"""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from api.main import app
from api.database import init_db

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def setup_test_database(tmp_path, monkeypatch):
    """Use an isolated temporary SQLite database for tests."""
    test_db = tmp_path / "test_posturelens.db"
    monkeypatch.setattr("api.database.DEFAULT_DB_PATH", test_db)
    init_db(test_db)
    yield


client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_get_policies_endpoint():
    response = client.get("/policies")
    assert response.status_code == 200
    policies = response.json()
    assert isinstance(policies, list)
    assert len(policies) >= 10
    
    # Verify metadata fields
    p = policies[0]
    assert "id" in p
    assert "category" in p
    assert "severity" in p
    assert "title" in p
    assert "description" in p


def test_scan_upload_clean_dockerfile():
    file_path = FIXTURES_DIR / "dockerfiles" / "Dockerfile.clean"
    with open(file_path, "rb") as f:
        response = client.post(
            "/scan",
            files={"file": ("Dockerfile.clean", f, "text/plain")}
        )

    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "Dockerfile.clean"
    assert data["file_type"] == "dockerfile"
    assert data["risk_score"] == 0
    assert data["risk_level"] == "CLEAN"
    assert data["total_violations"] == 0
    assert "id" in data


def test_scan_upload_misconfigured_dockerfile():
    file_path = FIXTURES_DIR / "dockerfiles" / "Dockerfile.misconfigured"
    with open(file_path, "rb") as f:
        response = client.post(
            "/scan",
            files={"file": ("Dockerfile.misconfigured", f, "text/plain")}
        )

    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "Dockerfile.misconfigured"
    assert data["file_type"] == "dockerfile"
    assert data["risk_score"] > 0
    assert data["total_violations"] >= 5


def test_scan_upload_misconfigured_k8s_manifest():
    file_path = FIXTURES_DIR / "k8s" / "misconfigured_pod.yaml"
    with open(file_path, "rb") as f:
        response = client.post(
            "/scan",
            files={"file": ("misconfigured_pod.yaml", f, "application/x-yaml")}
        )

    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "misconfigured_pod.yaml"
    assert data["file_type"] == "k8s"
    assert data["risk_score"] >= 30
    assert data["total_violations"] >= 5


def test_scans_history_and_detail_flow():
    # 1. Initially scans history is empty
    resp_init = client.get("/scans")
    assert resp_init.status_code == 200
    assert resp_init.json() == []

    # 2. Upload clean pod manifest
    clean_k8s = FIXTURES_DIR / "k8s" / "clean_pod.yaml"
    with open(clean_k8s, "rb") as f:
        up_resp = client.post(
            "/scan",
            files={"file": ("clean_pod.yaml", f, "application/x-yaml")}
        )
    assert up_resp.status_code == 200
    scan_id = up_resp.json()["id"]

    # 3. Check /scans history list
    list_resp = client.get("/scans")
    assert list_resp.status_code == 200
    scans_list = list_resp.json()
    assert len(scans_list) == 1
    assert scans_list[0]["id"] == scan_id
    assert scans_list[0]["filename"] == "clean_pod.yaml"

    # 4. Fetch detail via /scans/{id}
    detail_resp = client.get(f"/scans/{scan_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["id"] == scan_id
    assert "scan_result" in detail
    assert "parsed_data" in detail["scan_result"]
    assert "policy_report" in detail["scan_result"]


def test_scan_detail_not_found():
    response = client.get("/scans/999999")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()
