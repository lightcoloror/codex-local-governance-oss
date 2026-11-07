"""Offline structural, payload and referenced-byte integrity checks.

This does not run task capsules or grant execution/publication authority.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry

class CapsuleError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_json(path: Path, error_code: str = "SCHEMA_INVALID") -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CapsuleError(error_code, f"missing_file:{path}") from exc
    except json.JSONDecodeError as exc:
        raise CapsuleError(error_code, f"invalid_json:{path}:{exc}") from exc
    if not isinstance(value, dict):
        raise CapsuleError(error_code, f"document_not_object:{path}")
    return value


def _payload_sha256(value: dict[str, Any]) -> str:
    candidate = copy.deepcopy(value)
    candidate.pop("payload_sha256", None)
    return sha256_bytes(canonical_bytes(candidate))


def _validate_payload(value: dict[str, Any], code: str) -> None:
    if value.get("payload_sha256") != _payload_sha256(value):
        raise CapsuleError(code, "payload_sha256")


def _resolve_inside(root: Path, relative: str, code: str) -> Path:
    if re.match(r"^[A-Za-z]:[\\/]", relative) or relative.startswith(("/", "\\")):
        raise CapsuleError(code, f"absolute_path:{relative}")
    target = (root / relative).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError as exc:
        raise CapsuleError(code, f"path_escape:{relative}") from exc
    return target

SCHEMAS = Path(__file__).resolve().parent / "governance_assets" / "schemas"

def validate_document(value: dict[str, Any], schema_path: Path) -> None:
    schema = load_json(schema_path)
    Draft202012Validator.check_schema(schema)
    errors = list(Draft202012Validator(schema, registry=Registry(), format_checker=FormatChecker()).iter_errors(value))
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path) or "$"
        raise CapsuleError("SCHEMA_INVALID", f"{schema_path.name}:{location}:{first.message}")

def _refs(value: Any):
    if isinstance(value, dict):
        if set(value) == {"path", "sha256"}:
            yield value
        for child in value.values():
            yield from _refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from _refs(child)

def verify(schema_path: Path, document: Path, root: Path | None = None) -> dict[str, Any]:
    value = load_json(document)
    validate_document(value, schema_path)
    payload_checked = "payload_sha256" in value
    if payload_checked:
        _validate_payload(value, "PAYLOAD_HASH_DRIFT")
    refs = list(_refs(value))
    if refs and root is None:
        raise CapsuleError("INPUT_ROOT_REQUIRED", "Referenced bytes require an explicit input root")
    for ref in refs:
        path = _resolve_inside(root, ref["path"], "REFERENCE_PATH_VIOLATION")
        if sha256_file(path) != ref["sha256"]:
            raise CapsuleError("INPUT_HASH_DRIFT", ref["path"])
    return {"status":"passed", "schema_valid":True, "payload_hash_checked":payload_checked,
            "references_checked":len(refs), "execution_authorized":False,
            "evidence_truth":"not_assessed", "business_completion":"not_assessed"}

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", required=True, type=Path)
    parser.add_argument("--document", required=True, type=Path)
    parser.add_argument("--input-root", type=Path)
    args=parser.parse_args(argv)
    try:
        result=verify(args.schema,args.document,args.input_root)
    except Exception as exc:
        print(json.dumps({"status":"blocked","error":getattr(exc,"code","VALIDATION_FAILED"),"detail":str(exc)}),file=sys.stderr)
        return 2
    print(json.dumps(result,sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
