"""Extracted manifest validation support; no workspace discovery or execution."""
from __future__ import annotations
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterable
from jsonschema import Draft202012Validator
from referencing import Registry

PERSONAL_PATH_PATTERNS = (
    re.compile(r"(?<![A-Za-z])[A-Za-z]:[/\\]", re.IGNORECASE),
    re.compile(r"[A-Za-z]:[/\\]Users[/\\][^/\\\s]+", re.IGNORECASE),
    re.compile(r"[A-Za-z]:[/\\]documents[/\\]", re.IGNORECASE),
    re.compile(r"/home/[^/\s]+", re.IGNORECASE),
)


SECRET_VALUE_PATTERNS = (
    re.compile(r"\b(?:sk|ghp|github_pat)_[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)


class BundleError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BundleError("missing_file", str(path)) from exc
    except json.JSONDecodeError as exc:
        raise BundleError("invalid_json", f"{path}: {exc}") from exc


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def atomic_write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() == value:
        return
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def write_json(path: Path, value: Any) -> None:
    atomic_write(path, canonical_json_bytes(value))


def validate_schema(instance: Any, schema: dict[str, Any], label: str) -> None:
    errors = sorted(Draft202012Validator(schema, registry=Registry()).iter_errors(instance), key=lambda item: list(item.path))
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.path) or "$"
        raise BundleError("schema_validation_failed", f"{label}:{location}:{first.message}")


def iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from iter_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from iter_strings(item)


def scan_sensitive_values(value: Any, label: str) -> None:
    for text in iter_strings(value):
        for pattern in PERSONAL_PATH_PATTERNS:
            if pattern.search(text):
                raise BundleError("personal_path_detected", f"{label}:{pattern.pattern}")
        for pattern in SECRET_VALUE_PATTERNS:
            if pattern.search(text):
                raise BundleError("secret_value_detected", f"{label}:{pattern.pattern}")


def is_powershell_command(command: str) -> bool:
    lowered = command.lower()
    return "powershell" in lowered or ".ps1" in lowered


def validate_manifest_semantics(manifest: dict[str, Any], label: str) -> None:
    if manifest.get("notTrustedAsInstruction") is not True:
        raise BundleError("metadata_trust_boundary_missing", label)
    if manifest.get("executionAuthority") != "none_metadata_only":
        raise BundleError("execution_authority_forbidden", label)
    for interface in manifest.get("interfaces", {}).get("canonical", []):
        command = interface.get("command", "")
        if command and is_powershell_command(command):
            raise BundleError("powershell_cannot_be_canonical", f"{label}:{command}")
    scan_sensitive_values(manifest, label)
