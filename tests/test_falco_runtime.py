"""
Unit and integration tests for Falco runtime monitoring layer.
"""

import pytest
from fastapi.testclient import TestClient
from scanner import FalcoAlertNormalizer
from api.main import app
from api.database import init_db


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    test_db = tmp_path / "test_falco.db"
    monkeypatch.setattr("api.database.DEFAULT_DB_PATH", test_db)
    init_db(test_db)
    yield


client = TestClient(app)


def test_falco_alert_normalizer():
    payload = {
        "rule": "Terminal Shell in Container",
        "priority": "CRITICAL",
        "output": "Critical Terminal shell spawned in container",
        "output_fields": {
            "container.id": "a9f1b2c3d4e5",
            "k8s.pod.name": "web-pod-1",
            "k8s.ns.name": "production"
        }
    }

    normalized = FalcoAlertNormalizer.normalize(payload)
    assert normalized.rule_name == "Terminal Shell in Container"
    assert normalized.severity == "critical"
    assert normalized.container_id == "a9f1b2c3d4e5"
    assert normalized.pod_name == "web-pod-1"
    assert normalized.namespace == "production"
    assert "k8s.pod/production/web-pod-1/container/a9f1b2c3d4e5" in normalized.field_path


def test_receive_falco_webhook_api():
    payload = {
        "rule": "Read sensitive file in container",
        "priority": "ERROR",
        "output": "Error Sensitive file (/etc/shadow) opened",
        "output_fields": {
            "container.id": "b1c2d3e4f5a6",
            "k8s.pod.name": "payment-api-99",
            "k8s.ns.name": "finance"
        }
    }

    response = client.post("/falco/webhook", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ingested"
    assert "alert_id" in data
    assert data["normalized_alert"]["severity"] == "high"


def test_get_runtime_alerts_api():
    # Ingest test alert
    client.post("/falco/webhook", json={
        "rule": "Outbound Connection to Suspicious IP",
        "priority": "WARNING",
        "output": "Warning Outbound connection to 198.51.100.1",
        "output_fields": {"k8s.pod.name": "worker-1"}
    })

    response = client.get("/runtime-alerts")
    assert response.status_code == 200
    alerts = response.json()
    assert isinstance(alerts, list)
    assert len(alerts) >= 1
    assert alerts[0]["rule_name"] == "Outbound Connection to Suspicious IP"
    assert alerts[0]["severity"] == "medium"


def test_simulate_falco_alert_api():
    response = client.post("/falco/simulate")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "simulated"
    assert "alert_id" in data
