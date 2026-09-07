"""
Parsers for Dockerfiles, Docker Compose files, and Kubernetes manifests.
Includes AST-like line tracking for YAML mappings and sequences.
"""

from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import re
import yaml


class LineDict(dict):
    """A dictionary that stores the source line number where it was defined."""
    def __init__(self, *args, line: int = 1, **kwargs):
        super().__init__(*args, **kwargs)
        self.__line__ = line


class LineList(list):
    """A list that stores the source line number where it was defined."""
    def __init__(self, *args, line: int = 1, **kwargs):
        super().__init__(*args, **kwargs)
        self.__line__ = line


class LineNumberLoader(yaml.SafeLoader):
    """PyYAML Loader that preserves source line numbers for dicts and lists."""

    def construct_mapping(self, node, deep=False):
        mapping = super().construct_mapping(node, deep=deep)
        line = node.start_mark.line + 1  # 1-indexed
        return LineDict(mapping, line=line)

    def construct_sequence(self, node, deep=False):
        seq = super().construct_sequence(node, deep=deep)
        line = node.start_mark.line + 1  # 1-indexed
        return LineList(seq, line=line)


def get_line_number(obj: Any, default: int = 1) -> int:
    """Extract line number attached by LineNumberLoader if available."""
    if hasattr(obj, "__line__"):
        return getattr(obj, "__line__")
    return default


class DockerfileInstruction:
    """Represents a single parsed Dockerfile instruction."""
    def __init__(self, instruction: str, arguments: str, raw_line: str, line_number: int, stage_index: int = 0):
        self.instruction = instruction.upper()
        self.arguments = arguments.strip()
        self.raw_line = raw_line
        self.line_number = line_number
        self.stage_index = stage_index

    def __repr__(self) -> str:
        return f"<DockerfileInstruction {self.instruction} at line {self.line_number}: {self.arguments[:30]}>"


class DockerfileParser:
    """Parses Dockerfile into structured instructions with line tracking."""

    @staticmethod
    def parse_content(content: str) -> List[DockerfileInstruction]:
        lines = content.splitlines()
        instructions: List[DockerfileInstruction] = []
        current_instruction = ""
        current_arguments = ""
        current_raw = ""
        current_line_start = 1
        current_stage = 0
        in_continuation = False

        instruction_regex = re.compile(r"^\s*([A-Za-z]+)(?:\s+(.*)|$)", re.DOTALL)

        for line_idx, raw_line in enumerate(lines, 1):
            stripped = raw_line.strip()

            # Skip comments and empty lines if not in continuation
            if not in_continuation and (not stripped or stripped.startswith("#")):
                continue

            if not in_continuation:
                match = instruction_regex.match(raw_line)
                if match:
                    current_instruction = match.group(1).upper()
                    current_arguments = match.group(2) or ""
                    current_raw = raw_line
                    current_line_start = line_idx

                    if current_instruction == "FROM":
                        current_stage += 1

                    if stripped.endswith("\\"):
                        in_continuation = True
                        current_arguments = current_arguments.rstrip("\\").strip()
                    else:
                        instructions.append(
                            DockerfileInstruction(
                                instruction=current_instruction,
                                arguments=current_arguments,
                                raw_line=current_raw,
                                line_number=current_line_start,
                                stage_index=current_stage,
                            )
                        )
            else:
                # Inside continuation line
                current_raw += "\n" + raw_line
                if stripped.endswith("\\"):
                    current_arguments += " " + stripped.rstrip("\\").strip()
                else:
                    current_arguments += " " + stripped
                    in_continuation = False
                    instructions.append(
                        DockerfileInstruction(
                            instruction=current_instruction,
                            arguments=current_arguments,
                            raw_line=current_raw,
                            line_number=current_line_start,
                            stage_index=current_stage,
                        )
                    )

        return instructions

    @classmethod
    def parse_file(cls, file_path: str) -> List[DockerfileInstruction]:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return cls.parse_content(content)


class YamlParser:
    """Parses single and multi-document YAML files with line tracking."""

    @staticmethod
    def parse_content(content: str) -> List[Dict[str, Any]]:
        import textwrap
        content = textwrap.dedent(content)
        documents = []
        try:
            for doc in yaml.load_all(content, Loader=LineNumberLoader):
                if doc is not None and isinstance(doc, dict):
                    documents.append(doc)
        except Exception as e:
            # Fallback to standard safe_load if custom loader encounters edge cases
            try:
                for doc in yaml.safe_load_all(content):
                    if doc is not None and isinstance(doc, dict):
                        documents.append(doc)
            except Exception:
                raise e
        return documents


    @classmethod
    def parse_file(cls, file_path: str) -> List[Dict[str, Any]]:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return cls.parse_content(content)


class FileClassifier:
    """Identifies the file type for auditing (Dockerfile, Compose, Kubernetes, or Unknown)."""

    DOCKERFILE_NAMES = {"dockerfile", "containerfile"}
    COMPOSE_PATTERNS = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}

    @classmethod
    def classify_file(cls, file_path: str) -> str:
        path = Path(file_path)
        name_lower = path.name.lower()

        if name_lower in cls.DOCKERFILE_NAMES or name_lower.startswith("dockerfile.") or name_lower.endswith(".dockerfile"):
            return "dockerfile"

        if name_lower in cls.COMPOSE_PATTERNS or "docker-compose" in name_lower:
            return "compose"

        if path.suffix.lower() in {".yaml", ".yml"}:
            # Deep inspection of YAML contents
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                docs = YamlParser.parse_content(content)
                if not docs:
                    return "unknown"

                for doc in docs:
                    if cls.is_kubernetes_manifest(doc):
                        return "kubernetes"
                    if cls.is_docker_compose(doc):
                        return "compose"
            except Exception:
                return "unknown"

        return "unknown"

    @staticmethod
    def is_kubernetes_manifest(doc: Dict[str, Any]) -> bool:
        """Check if parsed YAML document matches Kubernetes resource schema."""
        if not isinstance(doc, dict):
            return False
        has_api = "apiVersion" in doc
        has_kind = "kind" in doc
        known_kinds = {
            "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob",
            "ReplicaSet", "ReplicationController", "Service", "ConfigMap",
            "Secret", "Ingress", "Namespace", "Role", "ClusterRole"
        }
        if has_api and has_kind:
            return True
        if has_kind and doc.get("kind") in known_kinds:
            return True
        return False

    @staticmethod
    def is_docker_compose(doc: Dict[str, Any]) -> bool:
        """Check if parsed YAML document matches Docker Compose schema."""
        if not isinstance(doc, dict):
            return False
        if "services" in doc and isinstance(doc["services"], dict):
            return True
        if "version" in doc and "services" in doc:
            return True
        return False
