"""
Dockerfile Parser module for PostureLens Container Security Posture Tool.
Uses `dockerfile-parse` to extract structured security metadata from Dockerfiles.
"""

import io
from typing import List, Dict, Optional
from pathlib import Path
from pydantic import BaseModel, Field
from dockerfile_parse import DockerfileParser


class BaseImageInfo(BaseModel):
    """Information about a FROM instruction base image."""
    image: str
    alias: Optional[str] = None
    stage_index: int
    is_latest_tag: bool = False


class CopyAddInstruction(BaseModel):
    """Information about COPY or ADD instructions."""
    instruction_type: str  # "COPY" or "ADD"
    source: str
    destination: str
    flags: List[str] = Field(default_factory=list)
    from_stage: Optional[str] = None
    is_add: bool = False


class ExposedPortInfo(BaseModel):
    """Information about EXPOSE instructions."""
    port: str
    protocol: str = "tcp"
    raw_instruction: str


class EnvVarInfo(BaseModel):
    """Information about ENV instructions."""
    key: str
    value: str
    is_potentially_sensitive: bool = False


class DockerfileScanResult(BaseModel):
    """Structured security metadata extracted from a Dockerfile."""
    file_path: Optional[str] = None
    base_images: List[BaseImageInfo] = Field(default_factory=list)
    final_base_image: Optional[str] = None
    user_instructions: List[str] = Field(default_factory=list)
    final_user: str = "root"
    is_root_user: bool = True
    exposed_ports: List[ExposedPortInfo] = Field(default_factory=list)
    env_vars: List[EnvVarInfo] = Field(default_factory=list)
    copy_add_instructions: List[CopyAddInstruction] = Field(default_factory=list)
    has_add_instructions: bool = False
    total_instructions: int = 0


class DockerfileAnalyzer:
    """Analyzer class for parsing Dockerfiles and returning structured security metadata."""

    SENSITIVE_ENV_KEYWORDS = [
        "SECRET", "KEY", "TOKEN", "PASSWORD", "PASS", "AUTH",
        "CREDENTIAL", "PRIVATE", "APIKEY", "API_KEY"
    ]

    def __init__(self, file_path: Optional[str] = None, content: Optional[str] = None):
        """
        Initialize the analyzer with a file path or direct string content.
        """
        if file_path is None and content is None:
            raise ValueError("Either file_path or content must be provided.")
        
        self.file_path = file_path
        if file_path:
            path_obj = Path(file_path)
            if not path_obj.exists() or not path_obj.is_file():
                raise FileNotFoundError(f"Dockerfile not found at {file_path}")
            raw_bytes = path_obj.read_bytes()
            self.parser = DockerfileParser(fileobj=io.BytesIO(raw_bytes))
        else:
            raw_bytes = (content or "").encode("utf-8")
            self.parser = DockerfileParser(fileobj=io.BytesIO(raw_bytes))

    def analyze(self) -> DockerfileScanResult:
        """
        Parse the Dockerfile and extract structured security relevant data.
        """
        structure = self.parser.structure
        
        base_images: List[BaseImageInfo] = []
        user_instructions: List[str] = []
        exposed_ports: List[ExposedPortInfo] = []
        env_vars: List[EnvVarInfo] = []
        copy_add_instructions: List[CopyAddInstruction] = []
        has_add = False
        stage_count = 0

        for item in structure:
            instruction = item.get("instruction", "").upper()
            value = item.get("value", "").strip()

            if instruction == "FROM":
                stage_count += 1
                parts = value.split()
                image_name = parts[0] if parts else value
                alias = None
                if len(parts) >= 3 and parts[1].upper() == "AS":
                    alias = parts[2]

                # Check if image tag is latest or missing explicit tag
                is_latest = False
                if ":" in image_name:
                    tag = image_name.split(":")[-1]
                    if tag.lower() == "latest":
                        is_latest = True
                else:
                    # No tag specified defaults to latest
                    is_latest = True

                base_images.append(
                    BaseImageInfo(
                        image=image_name,
                        alias=alias,
                        stage_index=stage_count,
                        is_latest_tag=is_latest
                    )
                )

            elif instruction == "USER":
                user_instructions.append(value)

            elif instruction == "EXPOSE":
                # Handle single or multiple ports e.g., EXPOSE 80 443/tcp
                port_tokens = value.split()
                for token in port_tokens:
                    if "/" in token:
                        port_num, proto = token.split("/", 1)
                    else:
                        port_num, proto = token, "tcp"
                    exposed_ports.append(
                        ExposedPortInfo(
                            port=port_num,
                            protocol=proto,
                            raw_instruction=value
                        )
                    )

            elif instruction == "ENV":
                # Extract key value pairs
                env_dict = self._parse_env_instruction(value)
                for key, val in env_dict.items():
                    is_sensitive = any(
                        kw in key.upper() for kw in self.SENSITIVE_ENV_KEYWORDS
                    )
                    env_vars.append(
                        EnvVarInfo(
                            key=key,
                            value=val,
                            is_potentially_sensitive=is_sensitive
                        )
                    )

            elif instruction in ("COPY", "ADD"):
                is_add_inst = (instruction == "ADD")
                if is_add_inst:
                    has_add = True

                copy_add_info = self._parse_copy_add(instruction, value)
                copy_add_instructions.append(copy_add_info)

        final_base = base_images[-1].image if base_images else None
        final_user = user_instructions[-1] if user_instructions else "root"
        
        # Determine if user is root (root, 0, root:root, 0:0, etc.)
        is_root = final_user.lower() in ("root", "0", "0:0", "root:root")

        return DockerfileScanResult(
            file_path=self.file_path,
            base_images=base_images,
            final_base_image=final_base,
            user_instructions=user_instructions,
            final_user=final_user,
            is_root_user=is_root,
            exposed_ports=exposed_ports,
            env_vars=env_vars,
            copy_add_instructions=copy_add_instructions,
            has_add_instructions=has_add,
            total_instructions=len(structure)
        )

    def _parse_env_instruction(self, value: str) -> Dict[str, str]:
        """Parse key-value pairs from ENV instruction string."""
        env_dict = {}
        # Simple key=val or KEY val format
        if "=" in value:
            # e.g., ENV VAR1=VAL1 VAR2=VAL2
            parts = value.split()
            for part in parts:
                if "=" in part:
                    k, v = part.split("=", 1)
                    env_dict[k.strip()] = v.strip('"\'')
        else:
            # e.g., ENV VAR1 VAL1
            parts = value.split(maxsplit=1)
            if len(parts) == 2:
                env_dict[parts[0].strip()] = parts[1].strip('"\'')
            elif len(parts) == 1:
                env_dict[parts[0].strip()] = ""
        return env_dict

    def _parse_copy_add(self, inst_type: str, value: str) -> CopyAddInstruction:
        """Parse COPY or ADD instruction into source, destination, and flags."""
        tokens = value.split()
        flags = []
        args = []
        from_stage = None

        for token in tokens:
            if token.startswith("--"):
                flags.append(token)
                if token.startswith("--from="):
                    from_stage = token.split("=", 1)[1]
            else:
                args.append(token)

        src = args[0] if len(args) > 0 else ""
        dest = args[1] if len(args) > 1 else ""

        return CopyAddInstruction(
            instruction_type=inst_type,
            source=src,
            destination=dest,
            flags=flags,
            from_stage=from_stage,
            is_add=(inst_type == "ADD")
        )
