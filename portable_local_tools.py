from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "agent-tool-manifest.v1"
CONFIG_VERSION = "portable-local-tools-manifest-sources.v1"
RCP_COMMIT = "b99d1bf20d535e82222bf5e654a0bfec2161f4ee"
RCP_LOADER_SHA256 = "f8f9e4903d97c4326cd54d7653e7c56bebcc87d24d3823d023f5f402f2e055a5"
RCP_SCHEMA_SHA256 = "5cd6a9fa0f36f1e4ea2b0e9cfd30c6354cf98ef8a16681525c9efe90e98e74c5"


class ConvergenceError(RuntimeError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConvergenceError("missing_file", str(path)) from exc
    except json.JSONDecodeError as exc:
        raise ConvergenceError("invalid_json", f"{path}:{exc}") from exc


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _load_rcp_adapter(rcp_root: Path) -> tuple[Any, dict[str, Any]]:
    rcp_root = rcp_root.resolve()
    loader = rcp_root / "src" / "portable_contract_bundle.py"
    schema_path = rcp_root / "portability" / "schemas" / "agent-tool-manifest.v1.schema.json"
    if not loader.is_file() or not schema_path.is_file():
        raise ConvergenceError("rcp_portable_adapter_missing", str(rcp_root))
    if sha256_file(loader) != RCP_LOADER_SHA256:
        raise ConvergenceError("rcp_loader_hash_drift", str(loader))
    if sha256_file(schema_path) != RCP_SCHEMA_SHA256:
        raise ConvergenceError("rcp_schema_hash_drift", str(schema_path))
    spec = importlib.util.spec_from_file_location("rcp_portable_contract_bundle_pinned", loader)
    if spec is None or spec.loader is None:
        raise ConvergenceError("rcp_loader_import_failed", str(loader))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, read_json(schema_path)






def _load_config(pack_root: Path) -> dict[str, Any]:
    config = read_json(pack_root / "manifest-sources.v1.json")
    if not isinstance(config, dict):
        raise ConvergenceError("invalid_config", "expected object")
    if config.get("schema_version") != CONFIG_VERSION:
        raise ConvergenceError("config_schema_mismatch", str(config.get("schema_version")))
    manifests = config.get("manifests", [])
    if not isinstance(manifests, list) or not manifests or len(manifests) > 256:
        raise ConvergenceError("invalid_manifest_set", "expected 1 to 256 manifests")
    ids = tuple(item.get("id") if isinstance(item, dict) else None for item in manifests)
    if any(not isinstance(item, str) or re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,79}", item) is None for item in ids):
        raise ConvergenceError("invalid_tool_id", repr(ids))
    if len(set(ids)) != len(ids):
        raise ConvergenceError("duplicate_tool_id", repr(ids))
    return config


def _validate_manifest(manifest: dict[str, Any], rcp_module: Any, schema: dict[str, Any]) -> None:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ConvergenceError("manifest_schema_mismatch", str(manifest.get("schema_version")))
    try:
        rcp_module.validate_schema(manifest, schema, manifest.get("id", "unknown"))
        rcp_module.validate_manifest_semantics(manifest, manifest.get("id", "unknown"))
    except Exception as exc:
        code = getattr(exc, "code", "rcp_manifest_validation_failed")
        raise ConvergenceError(code, str(exc)) from exc


def _manifest_path(pack_root: Path, tool_id: str) -> Path:
    return pack_root / "manifests" / tool_id / "agent-tool-manifest.v1.json"


def build(pack_root: Path, rcp_root: Path) -> dict[str, Any]:
    pack_root = pack_root.resolve()
    config = _load_config(pack_root)
    rcp_module, schema = _load_rcp_adapter(rcp_root)
    hashes: dict[str, str] = {}
    for manifest in config["manifests"]:
        _validate_manifest(manifest, rcp_module, schema)
        destination = _manifest_path(pack_root, manifest["id"])
        rcp_module.write_json(destination, manifest)
        hashes[manifest["id"]] = sha256_file(destination)
    return {
        "schema_version": "portable-local-tools-build.v1",
        "status": "ok",
        "tool_count": len(hashes),
        "tool_ids": list(hashes),
        "manifest_hashes": hashes,
        "semantic_sha256": sha256_bytes(canonical_bytes(hashes)),
        "rcp_commit": RCP_COMMIT,
        "metadata_authorizes_execution": False,
    }


def validate(pack_root: Path, rcp_root: Path) -> dict[str, Any]:
    pack_root = pack_root.resolve()
    _load_config(pack_root)
    rcp_module, schema = _load_rcp_adapter(rcp_root)
    hashes: dict[str, str] = {}
    for tool_id in (item["id"] for item in _load_config(pack_root)["manifests"]):
        path = _manifest_path(pack_root, tool_id)
        manifest = read_json(path)
        if manifest.get("id") != tool_id:
            raise ConvergenceError("manifest_id_mismatch", f"{tool_id}:{manifest.get('id')}")
        _validate_manifest(manifest, rcp_module, schema)
        hashes[tool_id] = sha256_file(path)
    return {
        "schema_version": "portable-local-tools-validation.v1",
        "status": "ok",
        "tool_count": len(hashes),
        "tool_ids": list(hashes),
        "manifest_hashes": hashes,
        "semantic_sha256": sha256_bytes(canonical_bytes(hashes)),
        "rcp_commit": RCP_COMMIT,
        "metadata_authorizes_execution": False,
    }


def _resolve_inside(root: Path, relative: str) -> Path:
    if Path(relative).is_absolute() or re.match(r"^[A-Za-z]:[\\/]", relative) or relative.startswith("\\") :
        raise ConvergenceError("absolute_check_path_forbidden", relative)
    root = root.resolve()
    candidate = (root / relative).resolve()
    if candidate != root and root not in candidate.parents:
        raise ConvergenceError("check_path_escape", relative)
    return candidate


def _run_check(workspace_root: Path, check: dict[str, Any]) -> dict[str, Any]:
    relative = str(check.get("path", ""))
    path = _resolve_inside(workspace_root, relative)
    kind = check.get("kind", "file")
    if kind == "file":
        ok = path.is_file()
    elif kind == "directory":
        ok = path.is_dir()
    else:
        raise ConvergenceError("unsupported_no_write_check", str(kind))
    contains = check.get("contains")
    if ok and contains is not None:
        try:
            ok = str(contains) in path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            ok = False
    return {
        "id": check.get("id"),
        "kind": kind,
        "path": relative.replace("\\", "/"),
        "status": "passed" if ok else "missing_or_mismatch",
        "required": check.get("required", True),
    }


def doctor(tool_id: str, pack_root: Path, workspace_root: Path, rcp_root: Path) -> dict[str, Any]:
    if tool_id not in {item["id"] for item in _load_config(pack_root)["manifests"]}:
        raise ConvergenceError("unknown_tool", tool_id)
    rcp_module, schema = _load_rcp_adapter(rcp_root)
    manifest = read_json(_manifest_path(pack_root.resolve(), tool_id))
    if manifest.get("id") != tool_id:
        raise ConvergenceError("manifest_id_mismatch", tool_id)
    _validate_manifest(manifest, rcp_module, schema)
    checks = [
        _run_check(workspace_root.resolve(), item)
        for item in manifest.get("provenance", {}).get("no_write_checks", [])
    ]
    required_failures = [item["id"] for item in checks if item["required"] and item["status"] != "passed"]
    runtime_contract = manifest.get("provenance", {}).get("runtime_contract", {})
    lifecycle_status = runtime_contract.get("lifecycle_status", "active")
    retired = lifecycle_status == "retired_disabled"
    if retired:
        status = "retired_disabled" if not required_failures else "blocked_retirement_evidence_missing"
    else:
        status = "ready_metadata_only" if not required_failures else "blocked_not_configured"
    return {
        "schema_version": "portable-local-tool-doctor.v1",
        "tool_id": tool_id,
        "status": status,
        "manifest_valid": True,
        "checks": checks,
        "required_failures": required_failures,
        "registration": "manifest_valid",
        "runtime": "retired_disabled" if retired else "not_assessed",
        "ui": "not_assessed",
        "actionability": "disabled_no_execution_authority" if retired else "metadata_only_no_execution_authority",
        "current_online": False if retired else "unknown",
        "lifecycle_status": lifecycle_status,
        "runtime_probe_performed": False,
        "network_performed": False,
        "write_performed": False,
        "metadata_authorizes_execution": False,
    }


def doctor_all(pack_root: Path, workspace_root: Path, rcp_root: Path) -> dict[str, Any]:
    tools = {
        tool_id: doctor(tool_id, pack_root, workspace_root, rcp_root)
        for tool_id in (item["id"] for item in _load_config(pack_root)["manifests"])
    }
    ready = sum(item["status"] == "ready_metadata_only" for item in tools.values())
    retired = sum(item["status"] == "retired_disabled" for item in tools.values())
    return {
        "schema_version": "portable-local-tools-doctor-summary.v1",
        "status": "ok" if ready + retired == len(tools) else "partial",
        "tool_count": len(tools),
        "ready_metadata_only_count": ready,
        "retired_disabled_count": retired,
        "tools": tools,
        "network_performed": False,
        "write_performed": False,
        "metadata_authorizes_execution": False,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Build, validate, and inspect Local Tools metadata-only manifests.")
    result.add_argument("--pack-root", type=Path, required=True)
    result.add_argument("--rcp-root", type=Path, default=Path(__file__).resolve().parent / "governance_assets")
    sub = result.add_subparsers(dest="command", required=True)
    sub.add_parser("build")
    sub.add_parser("validate")
    doctor_parser = sub.add_parser("doctor")
    doctor_parser.add_argument("--tool-id", required=True)
    doctor_parser.add_argument("--workspace-root", required=True, type=Path)
    doctor_all_parser = sub.add_parser("doctor-all")
    doctor_all_parser.add_argument("--workspace-root", required=True, type=Path)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.rcp_root is None:
            raise ConvergenceError("rcp_root_required", args.command)
        if args.command == "build":
            payload = build(args.pack_root, args.rcp_root)
        elif args.command == "validate":
            payload = validate(args.pack_root, args.rcp_root)
        elif args.command == "doctor":
            payload = doctor(args.tool_id, args.pack_root, args.workspace_root, args.rcp_root)
        else:
            payload = doctor_all(args.pack_root, args.workspace_root, args.rcp_root)
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0 if payload.get("status") in {"ok", "ready_metadata_only", "retired_disabled"} else 2
    except ConvergenceError as exc:
        print(json.dumps({"status": "blocked", "error": exc.code, "detail": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
