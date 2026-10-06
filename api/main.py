"""
FastAPI Application for PostureLens Container & K8s Security Posture Tool.
Includes SQLite persistence, OPA policy evaluation, Falco runtime monitoring, CORS, and full API endpoints.
"""

from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from scanner import (
    DockerfileAnalyzer,
    K8sManifestAnalyzer,
    OPAEngine,
    FalcoAlertNormalizer,
)
from scanner.policy_registry import list_loaded_policies, PolicyRuleMetadata
from .database import (
    init_db,
    save_scan,
    get_all_scans,
    get_scan_by_id,
    save_runtime_alert,
    get_runtime_alerts,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database on startup
    init_db()
    yield


app = FastAPI(
    title="PostureLens Security API",
    description="Container & Kubernetes Security Posture Scanner and Falco Runtime Monitoring API",
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Enable CORS for React frontend (localhost:3000 / localhost:5173)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OPA Engine singleton instance
opa_engine = OPAEngine()


def detect_file_type(filename: str, content: str) -> str:
    """Auto-detect whether file is a Kubernetes YAML or Dockerfile."""
    fn_lower = filename.lower()
    if fn_lower.endswith((".yaml", ".yml")):
        return "k8s"
    if "dockerfile" in fn_lower:
        return "dockerfile"

    if any(k in content for k in ("apiVersion:", "kind:", "metadata:", "spec:")):
        return "k8s"
    return "dockerfile"


@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "ok", "service": "PostureLens API", "version": "1.1.0"}


# --- Primary Static Scanner Endpoints ---

@app.post("/scan", tags=["Scanning"])
@app.post("/api/v1/scan", tags=["Scanning"])
async def scan_file_upload(file: UploadFile = File(...)):
    """
    Upload a Dockerfile or Kubernetes YAML manifest file for security scanning.
    Runs parsing -> OPA policy evaluation -> risk scoring and saves to scan history.
    """
    filename = file.filename or "uploaded_file"
    raw_bytes = await file.read()
    
    try:
        content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Uploaded file must be valid UTF-8 text.")

    if not content.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    file_type = detect_file_type(filename, content)

    try:
        if file_type == "k8s":
            analyzer = K8sManifestAnalyzer(content=content)
            parsed_result = analyzer.analyze()
            report = opa_engine.evaluate_k8s_manifest(parsed_result)
        else:
            analyzer = DockerfileAnalyzer(content=content)
            parsed_result = analyzer.analyze()
            report = opa_engine.evaluate_dockerfile(parsed_result)

        full_scan_dict = {
            "filename": filename,
            "file_type": file_type,
            "parsed_data": parsed_result.model_dump(),
            "policy_report": report.model_dump()
        }

        scan_id = save_scan(
            filename=filename,
            file_type=file_type,
            risk_score=report.risk_score.score,
            risk_level=report.risk_score.level,
            total_violations=len(report.violations),
            scan_result_dict=full_scan_dict
        )

        return {
            "id": scan_id,
            "filename": filename,
            "file_type": file_type,
            "risk_score": report.risk_score.score,
            "risk_level": report.risk_score.level,
            "total_violations": len(report.violations),
            "parsed_data": parsed_result.model_dump(),
            "policy_report": report.model_dump()
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Scan failed: {str(e)}")


@app.get("/scans", tags=["Scans"])
@app.get("/api/v1/scans", tags=["Scans"])
def list_scans():
    """Retrieve list of all past scans with summary risk metadata."""
    return get_all_scans()


@app.get("/scans/{scan_id}", tags=["Scans"])
@app.get("/api/v1/scans/{scan_id}", tags=["Scans"])
def get_scan_details(scan_id: int):
    """Retrieve full details, parsed findings, and OPA policy report for a scan by ID."""
    record = get_scan_by_id(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found.")
    return record


@app.get("/policies", response_model=List[PolicyRuleMetadata], tags=["Policies"])
@app.get("/api/v1/policies", response_model=List[PolicyRuleMetadata], tags=["Policies"])
def get_loaded_policies():
    """List all loaded OPA Rego policy rules with metadata (id, category, severity, description)."""
    return list_loaded_policies()


# --- Falco Runtime Monitoring Endpoints ---

@app.post("/falco/webhook", tags=["Falco Runtime"])
@app.post("/api/v1/falco/webhook", tags=["Falco Runtime"])
async def receive_falco_webhook(request: Request):
    """
    HTTP Webhook endpoint for receiving live JSON alert payloads from Falco daemon / Falcosidekick.
    Normalizes Falco alert priorities and stores runtime violations.
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload from Falco.")

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Falco payload must be a JSON object.")

    normalized = FalcoAlertNormalizer.normalize(payload)
    
    alert_id = save_runtime_alert(
        rule_id=normalized.rule_id,
        rule_name=normalized.rule_name,
        severity=normalized.severity,
        title=normalized.title,
        description=normalized.description,
        field_path=normalized.field_path,
        container_id=normalized.container_id,
        pod_name=normalized.pod_name,
        namespace=normalized.namespace,
        raw_payload_dict=normalized.raw_payload
    )

    return {
        "status": "ingested",
        "alert_id": alert_id,
        "normalized_alert": normalized.model_dump()
    }


@app.get("/runtime-alerts", tags=["Falco Runtime"])
@app.get("/api/v1/runtime-alerts", tags=["Falco Runtime"])
def list_runtime_alerts(limit: int = 100):
    """
    Retrieve list of ingested runtime security alerts from Falco.
    """
    return get_runtime_alerts(limit=limit)


@app.post("/falco/simulate", tags=["Falco Runtime"])
@app.post("/api/v1/falco/simulate", tags=["Falco Runtime"])
def simulate_falco_alert():
    """
    Helper test endpoint to inject a simulated Falco runtime violation alert into PostureLens.
    """
    simulated_payloads = [
        {
            "rule": "Terminal Shell in Container",
            "priority": "CRITICAL",
            "output": "14:22:01.102931: Critical Terminal shell (bash) spawned in container (user=root container_id=a9f1b2c3d4e5 container_name=web-app image=nginx:latest pod=nginx-prod-7d89b ns=prod cmdline=bash)",
            "output_fields": {
                "container.id": "a9f1b2c3d4e5",
                "container.name": "web-app",
                "k8s.pod.name": "nginx-prod-7d89b",
                "k8s.ns.name": "prod",
                "user.name": "root"
            }
        },
        {
            "rule": "Read sensitive file in container",
            "priority": "ERROR",
            "output": "14:23:45.882103: Error Sensitive file (/etc/shadow) opened for reading (user=appuser container_id=c4d3e2f1a0b9 pod=payment-service-84f2 ns=finance cmdline=cat /etc/shadow)",
            "output_fields": {
                "container.id": "c4d3e2f1a0b9",
                "container.name": "payment-api",
                "k8s.pod.name": "payment-service-84f2",
                "k8s.ns.name": "finance",
                "user.name": "appuser"
            }
        },
        {
            "rule": "Outbound Connection to C2 IP",
            "priority": "WARNING",
            "output": "14:25:12.339120: Warning Outbound network connection initiated to suspicious IP (user=root container_id=e5f6a7b8c9d0 pod=worker-node-12a ns=default dest=198.51.100.44:443)",
            "output_fields": {
                "container.id": "e5f6a7b8c9d0",
                "container.name": "background-worker",
                "k8s.pod.name": "worker-node-12a",
                "k8s.ns.name": "default",
                "user.name": "root"
            }
        }
    ]

    import random
    payload = random.choice(simulated_payloads)
    normalized = FalcoAlertNormalizer.normalize(payload)

    alert_id = save_runtime_alert(
        rule_id=normalized.rule_id,
        rule_name=normalized.rule_name,
        severity=normalized.severity,
        title=normalized.title,
        description=normalized.description,
        field_path=normalized.field_path,
        container_id=normalized.container_id,
        pod_name=normalized.pod_name,
        namespace=normalized.namespace,
        raw_payload_dict=normalized.raw_payload
    )

    return {
        "status": "simulated",
        "alert_id": alert_id,
        "normalized_alert": normalized.model_dump()
    }
