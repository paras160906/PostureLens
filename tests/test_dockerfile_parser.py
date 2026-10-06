"""
Unit tests for Dockerfile parser module.
"""

import pytest
from pathlib import Path
from scanner.dockerfile_parser import DockerfileAnalyzer, DockerfileScanResult

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "dockerfiles"


def test_clean_dockerfile():
    """Test parsing a well-configured multi-stage Dockerfile."""
    clean_path = FIXTURES_DIR / "Dockerfile.clean"
    analyzer = DockerfileAnalyzer(file_path=str(clean_path))
    result: DockerfileScanResult = analyzer.analyze()

    # Base image checks
    assert len(result.base_images) == 2
    assert result.base_images[0].image == "python:3.11-slim"
    assert result.base_images[0].alias == "builder"
    assert result.base_images[1].image == "python:3.11-slim"
    assert result.base_images[1].alias == "runner"
    assert result.final_base_image == "python:3.11-slim"

    # User directive checks
    assert result.user_instructions == ["appuser"]
    assert result.final_user == "appuser"
    assert result.is_root_user is False

    # Exposed ports
    assert len(result.exposed_ports) == 1
    assert result.exposed_ports[0].port == "8080"
    assert result.exposed_ports[0].protocol == "tcp"

    # COPY / ADD instructions
    assert result.has_add_instructions is False
    assert len(result.copy_add_instructions) == 3
    assert result.copy_add_instructions[1].from_stage == "builder"
    assert result.copy_add_instructions[1].instruction_type == "COPY"


def test_misconfigured_dockerfile():
    """Test parsing an insecure Dockerfile with multiple security issues."""
    misconfigured_path = FIXTURES_DIR / "Dockerfile.misconfigured"
    analyzer = DockerfileAnalyzer(file_path=str(misconfigured_path))
    result: DockerfileScanResult = analyzer.analyze()

    # Unpinned latest base image
    assert result.final_base_image == "ubuntu:latest"
    assert result.base_images[0].is_latest_tag is True

    # Missing USER directive -> defaults to root
    assert result.user_instructions == []
    assert result.final_user == "root"
    assert result.is_root_user is True

    # Dangerous ADD instructions
    assert result.has_add_instructions is True
    add_insts = [i for i in result.copy_add_instructions if i.is_add]
    assert len(add_insts) == 2

    # Exposed sensitive port (22)
    exposed_ports = [p.port for p in result.exposed_ports]
    assert "22" in exposed_ports
    assert "80" in exposed_ports
    assert "443" in exposed_ports

    # Sensitive ENV variables
    sensitive_envs = [e.key for e in result.env_vars if e.is_potentially_sensitive]
    assert "AWS_SECRET_ACCESS_KEY" in sensitive_envs


def test_dockerfile_from_string_content():
    """Test parsing raw Dockerfile string content."""
    content = """
    FROM alpine:3.18
    USER nonroot
    EXPOSE 9090
    ENV APP_PORT=9090
    COPY . /app
    """
    analyzer = DockerfileAnalyzer(content=content)
    result = analyzer.analyze()

    assert result.final_base_image == "alpine:3.18"
    assert result.final_user == "nonroot"
    assert result.is_root_user is False
    assert len(result.exposed_ports) == 1
    assert result.exposed_ports[0].port == "9090"


def test_missing_file_raises_error():
    """Test providing a non-existent file path raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        DockerfileAnalyzer(file_path="non_existent_Dockerfile")


def test_empty_arguments_raises_error():
    """Test initializing with neither file_path nor content raises ValueError."""
    with pytest.raises(ValueError):
        DockerfileAnalyzer()
