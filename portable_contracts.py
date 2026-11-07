"""Inspect the declared portable metadata bundle; never execute its commands."""
from __future__ import annotations

import argparse
from importlib import resources
import json
from pathlib import Path
import sys

import contract_integrity as integrity
import portable_local_tools as manifests

CONTRACT_IDS = {
    "material-manifest.v1", "evidence-bundle.v1", "content-brief.v1",
    "review-packet.v1", "service-profile.v1", "closure_run.v1", "local-tool-event.v1",
}


def default_root() -> Path:
    return Path(str(resources.files("governance_assets").joinpath("contracts/portable/v1")))


def _reference(root: Path, relative: str, digest: str) -> Path:
    path = integrity._resolve_inside(root, relative, "BUNDLE_PATH_VIOLATION")
    if not path.is_file() or integrity.sha256_file(path) != digest:
        raise integrity.CapsuleError("BUNDLE_HASH_DRIFT", relative)
    return path


def verify(bundle_root: Path | None = None) -> dict:
    root = (bundle_root or default_root()).resolve(strict=True)
    bundle = integrity.load_json(root / "portable-contract-bundle.v1.json")
    integrity.validate_document(bundle, root / "schemas/portable-contract-bundle.v1.schema.json")
    contracts = bundle["contracts"]
    if len({row["contract_id"] for row in contracts}) != 7 or {row["contract_id"] for row in contracts} != CONTRACT_IDS:
        raise integrity.CapsuleError("CONTRACT_SET_MISMATCH", "Seven unique declared contract IDs required")
    checked = []
    for section in ("artifacts", "mainchain_manifests", "contracts"):
        key = "bundle_ref" if section == "contracts" else "path"
        for row in bundle[section]:
            _reference(root, row[key], row["sha256"])
            if row[key] in checked:
                raise integrity.CapsuleError("DUPLICATE_BUNDLE_PATH", row[key])
            checked.append(row[key])
    proposal_path = _reference(root, bundle["proposal_ref"], bundle["proposal_sha256"])
    queue_path = _reference(root, bundle["difference_queue_ref"], bundle["difference_queue_sha256"])
    catalog_path = _reference(root, "sources/linkage-contract-catalog.v1.json", bundle["source_catalog_sha256"])
    _reference(root, "sources/public-toolchain.lock.json", bundle["registry_sha256"])
    catalog = integrity.load_json(catalog_path)
    integrity.validate_document(catalog, root / "schemas/linkage-contract-catalog.v1.schema.json")
    by_id = {row["contract_id"]: row for row in catalog["contracts"]}
    if len(by_id) != 5 or set(by_id) != CONTRACT_IDS - {"closure_run.v1", "local-tool-event.v1"}:
        raise integrity.CapsuleError("CATALOG_SET_DRIFT", "Five unique facade IDs required")
    for row in contracts:
        value = integrity.load_json(root / row["bundle_ref"])
        if value.get("contract_id") != row["contract_id"]:
            raise integrity.CapsuleError("CONTRACT_ID_DRIFT", row["contract_id"])
        if value.get("notTrustedAsInstruction") is not True or value.get("executionAuthority") != "none_metadata_only":
            raise integrity.CapsuleError("BUNDLE_AUTHORITY_DRIFT", row["contract_id"])
        if row["contract_id"] in by_id:
            if value.get("contract") != by_id[row["contract_id"]] or value.get("source_catalog_sha256") != bundle["source_catalog_sha256"] or value.get("source_catalog_ref") != "sources/linkage-contract-catalog.v1.json":
                raise integrity.CapsuleError("CONTRACT_CATALOG_DRIFT", row["contract_id"])
        else:
            _reference(root, value["schema_ref"], value["schema_sha256"])
    # Reuse the existing pinned generic manifest validator, not a private
    # workspace's tool discovery, inventory, routing or execution machinery.
    adapter, schema = manifests._load_rcp_adapter(Path(__file__).resolve().parent / "governance_assets")
    ids = []
    for row in bundle["mainchain_manifests"]:
        value = integrity.load_json(root / row["path"])
        manifests._validate_manifest(value, adapter, schema)
        if value["id"] != row["tool_id"] or value["id"] in ids:
            raise integrity.CapsuleError("MANIFEST_ID_DRIFT", row["tool_id"])
        ids.append(value["id"])
        refs = value.get("contract_refs", [])
        ref_ids = [ref["contract_id"] for ref in refs]
        if len(set(ref_ids)) != len(ref_ids) or not set(ref_ids) <= CONTRACT_IDS:
            raise integrity.CapsuleError("MANIFEST_CONTRACT_DRIFT", value["id"])
    proposal = integrity.load_json(proposal_path)
    if proposal.get("tool_count") != len(ids) or [m.get("id") for m in proposal.get("manifests", [])] != ids:
        raise integrity.CapsuleError("PROPOSAL_SCOPE_DRIFT", "Selected metadata source set differs")
    for row, expected in zip(proposal["manifests"], bundle["mainchain_manifests"], strict=True):
        if row != integrity.load_json(root / expected["path"]):
            raise integrity.CapsuleError("PROPOSAL_MANIFEST_DRIFT", expected["tool_id"])
    queue = integrity.load_json(queue_path)
    if queue.get("item_count") != 0 or queue.get("items") != []:
        raise integrity.CapsuleError("PRIVATE_INVENTORY_NOT_SUPPORTED", "No private remaining-tool queue belongs in this public subset")
    for label, value in (("bundle", bundle), ("catalog", catalog), ("proposal", proposal), ("queue", queue)):
        try:
            adapter.scan_sensitive_values(value, label)
        except adapter.BundleError as error:
            raise integrity.CapsuleError(error.code, str(error)) from error
    availability = integrity.load_json(root / "AVAILABILITY.json")
    if set(availability) != CONTRACT_IDS:
        raise integrity.CapsuleError("AVAILABILITY_SET_DRIFT", "Missing explicit contract boundary")
    for cid, value in availability.items():
        expected = ("blocked_external_native_owner_not_distributed" if cid == "review-packet.v1" else
                    "not_implemented_by_bundle" if cid in {"closure_run.v1", "local-tool-event.v1"} else "not_assessed")
        if value.get("runtime") != expected:
            raise integrity.CapsuleError("RUNTIME_CLAIM_DRIFT", cid)
    provenance = integrity.load_json(root / "SOURCE-PROVENANCE.json")
    bindings = [source for item in catalog["contracts"] for source in item["authoritative_source"]]
    if provenance.get("native_source_bindings") != bindings:
        raise integrity.CapsuleError("SOURCE_PROVENANCE_DRIFT", "Catalog source bindings differ")
    # Only these generic bundled schemas have self-contained positive examples.
    # Fingerprints/fixture URIs in them are invented shape data, not live files.
    examples = (
        ("fixtures/contracts/closure-run.v1.json", "schemas/local-tool-closure-run.v2.schema.json", None),
        ("fixtures/contracts/local-tool-event.v1.json", "schemas/local-tool-event.v1.schema.json", None),
        ("fixtures/contracts/service-profile.v1.json", "schemas/service-profile.v1.schema.json", "payload"),
        ("fixtures/native/content-video-brief.v1.json", "fixtures/native/content-video-brief.v1.schema.json", None),
    )
    for document, schema_path, key in examples:
        example = integrity.load_json(root / document)
        integrity.validate_document(example[key] if key else example, root / schema_path)
    return {
        "status": "passed", "bundle_sha256": integrity.sha256_file(root / "portable-contract-bundle.v1.json"),
        "contract_count": 7, "verified_referenced_files": len(checked) + 4,
        "declared_source_interface_count": len(ids), "private_inventory_loaded": False,
        "commands_executed": [], "network_performed": False, "write_performed": False,
        "native_runtime": "not_assessed", "evidence_truth": "not_assessed",
        "business_completion": "not_assessed", "metadata_authorizes_execution": False,
        "availability": availability,
        "synthetic_example_schemas_checked": len(examples),
        "synthetic_fingerprint_files_verified": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-root", type=Path, help="Explicit local bundle root; default is the installed package resource")
    args = parser.parse_args(argv)
    try:
        result = verify(args.bundle_root)
    except (OSError, ValueError, integrity.CapsuleError, manifests.ConvergenceError) as error:
        print(json.dumps({"status": "blocked", "code": getattr(error, "code", type(error).__name__), "error": str(error), "metadata_authorizes_execution": False}), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
