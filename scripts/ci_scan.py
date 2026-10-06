"""
PostureLens CI/CD Pull Request Security Scanner Script.

Scans changed Dockerfiles and Kubernetes YAML manifests by calling the PostureLens FastAPI /scan endpoint.
- Fails (exit 1) if any CRITICAL or HIGH severity violations are found.
- Passes (exit 0) with warnings if only MEDIUM or LOW findings exist.
- Formats readable summary for GitHub Actions logs and GITHUB_STEP_SUMMARY.
"""

import sys
import os
import json
import subprocess
import urllib.request
import urllib.error
import argparse
from pathlib import Path

# Ensure UTF-8 output on Windows terminals if possible
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def discover_changed_files(target_branch: str = None) -> list[str]:
    """Auto-detect Dockerfile and YAML files changed in Git PR or HEAD commit."""
    files_to_check = []
    
    # Determine base branch
    base_ref = target_branch or os.getenv("GITHUB_BASE_REF") or os.getenv("GITHUB_TARGET_BRANCH")
    
    cmd = []
    if base_ref:
        cmd = ["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"]
    else:
        # Fallback to compare HEAD against previous commit or git status
        cmd = ["git", "diff", "--name-only", "HEAD~1"]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        changed_lines = res.stdout.strip().splitlines()
        for line in changed_lines:
            line = line.strip()
            if not line:
                continue
            p = Path(line)
            if p.exists() and p.is_file():
                fn = p.name.lower()
                if "dockerfile" in fn or fn.endswith((".yaml", ".yml")):
                    files_to_check.append(str(p))
    except Exception as e:
        print(f"::warning::Git diff detection failed ({e}). Fallback: searching current workspace.")
    
    # If no files found via git diff, check git status for untracked/modified
    if not files_to_check:
        try:
            res = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True)
            for line in res.stdout.strip().splitlines():
                if len(line) > 3:
                    file_path = line[3:].strip().strip('"')
                    p = Path(file_path)
                    if p.exists() and p.is_file():
                        fn = p.name.lower()
                        if "dockerfile" in fn or fn.endswith((".yaml", ".yml")):
                            if str(p) not in files_to_check:
                                files_to_check.append(str(p))
        except Exception:
            pass

    return files_to_check


def upload_and_scan(file_path: str, api_url: str) -> dict:
    """Send multipart file upload request to PostureLens /scan API endpoint."""
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    filename = p.name
    content = p.read_bytes()

    boundary = "----PostureLensFormBoundary7MA4YWxkTrZu0gW"
    body = bytearray()
    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode("utf-8"))
    body.extend(b"Content-Type: application/octet-stream\r\n\r\n")
    body.extend(content)
    body.extend(f"\r\n--{boundary}--\r\n".encode("utf-8"))

    req = urllib.request.Request(
        url=api_url,
        data=bytes(body),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            resp_body = response.read().decode("utf-8")
            return json.loads(resp_body)
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"HTTP {e.code} error from PostureLens scan endpoint: {err_msg}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Failed to connect to PostureLens backend at {api_url}: {e.reason}")


def append_step_summary(markdown_content: str):
    """Write markdown summary to GITHUB_STEP_SUMMARY if present."""
    step_summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if step_summary_path:
        try:
            with open(step_summary_path, "a", encoding="utf-8") as f:
                f.write(markdown_content + "\n")
        except Exception as e:
            print(f"Warning: Could not write to GITHUB_STEP_SUMMARY: {e}")


def main():
    parser = argparse.ArgumentParser(description="PostureLens Security CI/CD PR Scanner")
    parser.add_argument("files", nargs="*", help="Files to scan (defaults to git changed files)")
    parser.add_argument("--url", default=os.getenv("POSTURELENS_API_URL", "http://127.0.0.1:8000/scan"),
                        help="PostureLens FastAPI /scan endpoint URL")
    parser.add_argument("--target-branch", help="Target branch for PR diff comparison (e.g. main)")

    args = parser.parse_args()

    files = args.files
    if not files:
        files = discover_changed_files(target_branch=args.target_branch)

    if not files:
        print("================================================================================")
        print("PostureLens Security Scan")
        print("================================================================================")
        print("Info: No Dockerfile or Kubernetes YAML manifest files changed to scan.")
        append_step_summary("### 🛡️ PostureLens Security Scan\n\n*No Dockerfiles or Kubernetes YAML files were changed in this PR.*")
        sys.exit(0)

    print("================================================================================")
    print("PostureLens Security Posture Scan")
    print(f"Target API Endpoint: {args.url}")
    print(f"Files to scan: {', '.join(files)}")
    print("================================================================================\n")

    has_critical_or_high = False
    total_violations_found = 0
    scanned_results = []

    for file_path in files:
        print(f"--> Scanning: {file_path}")
        try:
            result = upload_and_scan(file_path, args.url)
        except Exception as err:
            print(f"::error file={file_path}::Scan request failed: {err}")
            print(f"ERROR: Scan failed for {file_path}: {err}\n")
            has_critical_or_high = True
            continue

        scanned_results.append((file_path, result))
        
        file_type = result.get("file_type", "unknown")
        risk_score = result.get("risk_score", 0)
        risk_level = result.get("risk_level", "UNKNOWN")
        policy_report = result.get("policy_report", {})
        violations = policy_report.get("violations", [])
        
        total_violations_found += len(violations)

        print(f"    Result for {file_path}: Type={file_type}, RiskLevel={risk_level}, Score={risk_score}, Violations={len(violations)}")
        
        if not violations:
            print("    [PASSED CLEAN] No policy violations detected.\n")
            continue

        print("    VIOLATIONS FOUND:")
        print("    " + "-" * 76)
        
        for v in violations:
            rule_id = v.get("rule_id", "UNKNOWN")
            severity = str(v.get("severity", "LOW")).upper()
            title = v.get("title", "")
            field_path = v.get("field_path", "N/A")
            desc = v.get("description", "")

            if severity in ("CRITICAL", "HIGH"):
                has_critical_or_high = True
                # Print GitHub Actions error annotation
                print(f"::error file={file_path}::[{severity}] {rule_id}: {title} (Field: {field_path})")
            else:
                # Print GitHub Actions warning annotation
                print(f"::warning file={file_path}::[{severity}] {rule_id}: {title} (Field: {field_path})")

            print(f"    * [{severity}] {rule_id}: {title}")
            print(f"      - Field Path : {field_path}")
            print(f"      - Description: {desc}")

        print("    " + "-" * 76 + "\n")

    # Generate Summary Markdown for GitHub Step Summary
    md_summary = ["### 🛡️ PostureLens Security Scan Results\n"]
    md_summary.append("| File | Type | Risk Level | Score | Violations | Status |")
    md_summary.append("| --- | --- | --- | --- | --- | --- |")

    for file_path, res in scanned_results:
        f_type = res.get("file_type", "unknown")
        r_score = res.get("risk_score", 0)
        r_level = res.get("risk_level", "UNKNOWN")
        viols = res.get("policy_report", {}).get("violations", [])
        
        file_has_high = any(str(v.get("severity", "")).upper() in ("CRITICAL", "HIGH") for v in viols)
        
        if file_has_high:
            status_badge = "❌ FAILED (CRITICAL/HIGH)"
        elif viols:
            status_badge = "⚠️ WARNING (MEDIUM/LOW)"
        else:
            status_badge = "✅ PASSED CLEAN"
            
        md_summary.append(f"| `{file_path}` | `{f_type}` | **{r_level}** | {r_score} | {len(viols)} | {status_badge} |")

    md_summary.append("\n")
    append_step_summary("\n".join(md_summary))

    print("================================================================================")
    print("SCAN SUMMARY RESULTS:")
    print(f"Total Files Scanned: {len(scanned_results)}")
    print(f"Total Violations   : {total_violations_found}")
    
    if has_critical_or_high:
        print("\n❌ OVERALL SCAN FAILED: One or more CRITICAL or HIGH severity violations were detected.")
        print("Please address the high-severity security findings listed above before merging.")
        print("================================================================================")
        sys.exit(1)
    elif total_violations_found > 0:
        print("\n⚠️ OVERALL SCAN PASSED WITH WARNINGS: Only MEDIUM or LOW severity findings detected.")
        print("Review warnings and consider fixing them.")
        print("================================================================================")
        sys.exit(0)
    else:
        print("\n✅ OVERALL SCAN PASSED: All files are clean!")
        print("================================================================================")
        sys.exit(0)


if __name__ == "__main__":
    main()
