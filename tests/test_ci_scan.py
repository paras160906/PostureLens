"""
Unit tests for PostureLens CI/CD scanner script (scripts/ci_scan.py).
"""

import sys
import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.ci_scan import discover_changed_files, upload_and_scan, main


def test_discover_changed_files_with_mock_git():
    mock_git_output = "Dockerfile\ntests/fixtures/k8s/clean_pod.yaml\nREADME.md\n"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=mock_git_output, returncode=0)
        files = discover_changed_files()
        assert any("clean_pod.yaml" in f for f in files)
        # README.md should be ignored since it's not a Dockerfile or YAML
        assert not any("README.md" in f for f in files)


def test_upload_and_scan_file_not_found():
    with pytest.raises(FileNotFoundError):
        upload_and_scan("non_existent_file.yaml", "http://127.0.0.1:8000/scan")


def test_main_no_files_detected():
    with patch("scripts.ci_scan.discover_changed_files", return_value=[]):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
