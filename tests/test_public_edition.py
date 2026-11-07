import copy
import hashlib
import json
import shutil
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import contract_integrity as integrity
import portable_local_tools as portable

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "governance_assets"


def write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


@pytest.fixture
def sample(tmp_path):
    pack = tmp_path / "relocated" / "pack"
    shutil.copytree(ROOT / "examples/metadata-pack", pack)
    workspace = tmp_path / "relocated" / "workspace"
    shutil.copytree(ROOT / "examples/synthetic-workspace", workspace)
    return pack, workspace


def test_build_validate_and_relocation_metadata_only(sample):
    pack, workspace = sample
    first = portable.build(pack, ADAPTER)
    second = portable.build(pack, ADAPTER)
    assert first == second
    assert portable.validate(pack, ADAPTER)["manifest_hashes"] == first["manifest_hashes"]
    before = {p.relative_to(workspace).as_posix(): p.read_bytes() for p in workspace.rglob("*") if p.is_file()}
    summary = portable.doctor_all(pack, workspace, ADAPTER)
    after = {p.relative_to(workspace).as_posix(): p.read_bytes() for p in workspace.rglob("*") if p.is_file()}
    assert before == after
    assert summary["tool_count"] == 2
    assert summary["ready_metadata_only_count"] == 1
    assert summary["retired_disabled_count"] == 1
    assert summary["metadata_authorizes_execution"] is False
    active = summary["tools"]["example-active"]
    assert active["current_online"] == "unknown"
    assert active["runtime"] == "not_assessed"
    assert active["runtime_probe_performed"] is False
    assert active["write_performed"] is False
    assert active["network_performed"] is False


def test_retired_missing_evidence_never_becomes_ready(sample):
    pack, workspace = sample
    portable.build(pack, ADAPTER)
    (workspace / "example-retired/DISCOVERY.md").unlink()
    result = portable.doctor("example-retired", pack, workspace, ADAPTER)
    assert result["status"] == "blocked_retirement_evidence_missing"
    assert result["actionability"] == "disabled_no_execution_authority"
    assert result["current_online"] is False


def test_missing_active_component_blocks(sample):
    pack, workspace = sample
    portable.build(pack, ADAPTER)
    (workspace / "example-active/DISCOVERY.md").unlink()
    result = portable.doctor("example-active", pack, workspace, ADAPTER)
    assert result["status"] == "blocked_not_configured"
    assert result["required_failures"] == ["discovery"]


@pytest.mark.parametrize("tool_id", ["../outside", "/absolute", "C:\\outside", "a/b", "..", "a", "a\\b", None])
def test_config_ids_cannot_escape_pack(sample, tool_id):
    pack, _ = sample
    config = portable.read_json(pack / "manifest-sources.v1.json")
    config["manifests"][0]["id"] = tool_id
    write(pack / "manifest-sources.v1.json", config)
    with pytest.raises(portable.ConvergenceError):
        portable.build(pack, ADAPTER)
    assert not (pack / "manifests").exists()


def test_duplicate_config_ids_block_before_writing(sample):
    pack, _ = sample
    config = portable.read_json(pack / "manifest-sources.v1.json")
    config["manifests"][1]["id"] = config["manifests"][0]["id"]
    write(pack / "manifest-sources.v1.json", config)
    with pytest.raises(portable.ConvergenceError) as error:
        portable.build(pack, ADAPTER)
    assert error.value.code == "duplicate_tool_id"
    assert not (pack / "manifests").exists()


@pytest.mark.parametrize("path", ["../outside", "/outside", "C:/outside", "\\\\server\\share"])
def test_doctor_rejects_absolute_and_escaping_checks(sample, path):
    pack, workspace = sample
    portable.build(pack, ADAPTER)
    p = portable._manifest_path(pack, "example-active")
    manifest = portable.read_json(p)
    manifest["provenance"]["no_write_checks"][0]["path"] = path
    write(p, manifest)
    with pytest.raises(portable.ConvergenceError):
        portable.doctor("example-active", pack, workspace, ADAPTER)


def test_doctor_rejects_substituted_manifest_identity(sample):
    pack, workspace = sample
    portable.build(pack, ADAPTER)
    p = portable._manifest_path(pack, "example-active")
    manifest = portable.read_json(p)
    manifest["id"] = "substituted-example"
    write(p, manifest)
    with pytest.raises(portable.ConvergenceError) as error:
        portable.doctor("example-active", pack, workspace, ADAPTER)
    assert error.value.code == "manifest_id_mismatch"


def test_metadata_cannot_promote_unprobed_online_claim(sample):
    pack, workspace = sample
    portable.build(pack, ADAPTER)
    p = portable._manifest_path(pack, "example-active")
    manifest = portable.read_json(p)
    manifest["provenance"]["runtime_contract"].update(current_online=True, default_runtime="running")
    write(p, manifest)
    result = portable.doctor("example-active", pack, workspace, ADAPTER)
    assert result["current_online"] == "unknown"
    assert result["runtime"] == "not_assessed"


@pytest.mark.parametrize("field,value", [
    ("notTrustedAsInstruction", False), ("executionAuthority", "execute"),
    ("description", "synthetic " + "ghp_" + "1234567890abcdefghijkl"),
])
def test_manifest_authority_and_secret_boundaries(sample, field, value):
    pack, _ = sample
    config = portable.read_json(pack / "manifest-sources.v1.json")
    candidate = copy.deepcopy(config["manifests"][0])
    candidate[field] = value
    adapter, schema = portable._load_rcp_adapter(ADAPTER)
    with pytest.raises(portable.ConvergenceError):
        portable._validate_manifest(candidate, adapter, schema)


@pytest.mark.parametrize("command", ["powershell -File tool.ps1", "python C:/" + "Users/example/tool.py"])
def test_canonical_entry_cannot_be_machine_bound(sample, command):
    pack, _ = sample
    candidate = portable.read_json(pack / "manifest-sources.v1.json")["manifests"][0]
    candidate["interfaces"]["canonical"] = [{"kind": "cli", "command": command}]
    adapter, schema = portable._load_rcp_adapter(ADAPTER)
    with pytest.raises(portable.ConvergenceError):
        portable._validate_manifest(candidate, adapter, schema)


@pytest.mark.parametrize("relative", ["src/portable_contract_bundle.py", "portability/schemas/agent-tool-manifest.v1.schema.json"])
def test_pinned_support_drift_blocks(sample, tmp_path, relative):
    pack, _ = sample
    adapter = tmp_path / "drifted-adapter"
    shutil.copytree(ADAPTER, adapter)
    p = adapter / relative
    p.write_bytes(p.read_bytes() + b"\n")
    with pytest.raises(portable.ConvergenceError):
        portable.build(pack, adapter)


def test_all_distributed_schemas_are_valid_and_local_refs_only():
    files = list(integrity.SCHEMAS.glob("*.json"))
    assert len(files) == 25
    def refs(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "$ref":
                    yield child
                yield from refs(child)
        elif isinstance(value, list):
            for child in value:
                yield from refs(child)
    for p in files:
        schema = integrity.load_json(p)
        Draft202012Validator.check_schema(schema)
        assert all(ref.startswith("#") for ref in refs(schema)), p.name


@pytest.mark.parametrize("schema,document", [
    ("local-tool-task-request.v1.schema.json", "task-request.synthetic.json"),
    ("agent-tool-compact-selector-request.v1.schema.json", "selector-request.synthetic.json"),
    ("local-tool-task-receipt.v1.schema.json", "task-receipt.synthetic.json"),
])
def test_synthetic_documents_validate(schema, document):
    result = integrity.verify(integrity.SCHEMAS / schema, ROOT / "examples" / document, ROOT / "examples")
    assert result["status"] == "passed"
    assert result["execution_authorized"] is False
    assert result["evidence_truth"] == "not_assessed"
    if document.startswith("task-receipt"):
        assert result["payload_hash_checked"] is True
        assert result["references_checked"] == 4


@pytest.fixture
def receipt_copy(tmp_path):
    examples = tmp_path / "examples"
    shutil.copytree(ROOT / "examples", examples)
    return examples, examples / "task-receipt.synthetic.json"


def test_schema_pass_does_not_hide_payload_tampering(receipt_copy):
    examples, document = receipt_copy
    receipt = integrity.load_json(document)
    receipt["resume_entry"] = "changed synthetic instructions"
    write(document, receipt)
    with pytest.raises(integrity.CapsuleError) as error:
        integrity.verify(integrity.SCHEMAS / "local-tool-task-receipt.v1.schema.json", document, examples)
    assert error.value.code == "PAYLOAD_HASH_DRIFT"


def test_rehashed_receipt_does_not_hide_input_tampering(receipt_copy):
    examples, document = receipt_copy
    (examples / "receipt-inputs/capsule.json").write_text("changed bytes", encoding="utf-8")
    with pytest.raises(integrity.CapsuleError) as error:
        integrity.verify(integrity.SCHEMAS / "local-tool-task-receipt.v1.schema.json", document, examples)
    assert error.value.code == "INPUT_HASH_DRIFT"


@pytest.mark.parametrize("path", ["../outside.json", "/outside.json", "C:/outside.json", "\\\\server\\share"])
def test_hashed_receipt_cannot_read_outside_explicit_root(receipt_copy, path):
    examples, document = receipt_copy
    receipt = integrity.load_json(document)
    receipt["capsule"]["path"] = path
    receipt["payload_sha256"] = integrity._payload_sha256(receipt)
    write(document, receipt)
    with pytest.raises(integrity.CapsuleError) as error:
        integrity.verify(integrity.SCHEMAS / "local-tool-task-receipt.v1.schema.json", document, examples)
    assert error.value.code == "REFERENCE_PATH_VIOLATION"


def test_receipt_needs_explicit_reference_root(receipt_copy):
    _, document = receipt_copy
    with pytest.raises(integrity.CapsuleError) as error:
        integrity.verify(integrity.SCHEMAS / "local-tool-task-receipt.v1.schema.json", document)
    assert error.value.code == "INPUT_ROOT_REQUIRED"


def test_external_schema_reference_cannot_fetch(tmp_path):
    schema = tmp_path / "remote.json"
    write(schema, {"$ref": "https://example.invalid/never-retrieve.schema.json"})
    with pytest.raises(Exception):
        integrity.validate_document({}, schema)


def test_existing_synthetic_receipt_disallows_external_write(receipt_copy):
    examples, document = receipt_copy
    receipt = integrity.load_json(document)
    receipt["boundary_check"]["external_write"] = True
    receipt["payload_sha256"] = integrity._payload_sha256(receipt)
    write(document, receipt)
    with pytest.raises(integrity.CapsuleError) as error:
        integrity.verify(integrity.SCHEMAS / "local-tool-task-receipt.v1.schema.json", document, examples)
    assert error.value.code == "SCHEMA_INVALID"


def test_cli_reports_pass_and_blocked_truthfully(sample, capsys):
    pack, workspace = sample
    assert portable.main(["--pack-root", str(pack), "build"]) == 0
    assert portable.main(["--pack-root", str(pack), "doctor-all", "--workspace-root", str(workspace)]) == 0
    (workspace / "example-active/DISCOVERY.md").unlink()
    assert portable.main(["--pack-root", str(pack), "doctor-all", "--workspace-root", str(workspace)]) == 2
    assert '"status": "partial"' in capsys.readouterr().out

