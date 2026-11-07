"""Synthetic integrity and false-completion counterexamples; no native execution."""
import copy
import json
from pathlib import Path
import shutil

import pytest

import contract_integrity as integrity
import portable_contracts as portable

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / 'contracts/portable/v1'


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n', encoding='utf-8')


def seal(root):
    """Model an attacker updating hashes: semantic guards must still reject."""
    path = root / 'portable-contract-bundle.v1.json'
    doc = read(path)
    for section in ('artifacts', 'contracts', 'mainchain_manifests'):
        for row in doc[section]:
            rel = row['bundle_ref' if section == 'contracts' else 'path']
            row['sha256'] = integrity.sha256_file(root / rel)
    doc['source_catalog_sha256'] = integrity.sha256_file(root / 'sources/linkage-contract-catalog.v1.json')
    doc['proposal_sha256'] = integrity.sha256_file(root / doc['proposal_ref'])
    write(path, doc)


@pytest.fixture
def relocated(tmp_path):
    root = tmp_path / 'relocated' / 'bundle'
    shutil.copytree(BUNDLE, root)
    return root


def test_complete_relocated_bundle_is_read_only_and_not_runtime_pass(relocated):
    before = {p.relative_to(relocated).as_posix(): p.read_bytes() for p in relocated.rglob('*') if p.is_file()}
    result = portable.verify(relocated)
    assert result['contract_count'] == result['declared_source_interface_count'] == 7
    assert result['synthetic_example_schemas_checked'] == 4
    assert result['status'] == 'passed'
    assert result['native_runtime'] == result['evidence_truth'] == result['business_completion'] == 'not_assessed'
    assert result['metadata_authorizes_execution'] is False
    assert result['commands_executed'] == []
    assert result['network_performed'] is result['write_performed'] is False
    assert result['synthetic_fingerprint_files_verified'] is False
    assert result['availability']['review-packet.v1']['runtime'] == 'blocked_external_native_owner_not_distributed'
    assert before == {p.relative_to(relocated).as_posix(): p.read_bytes() for p in relocated.rglob('*') if p.is_file()}


def test_installed_resource_mirror_is_exact():
    root = portable.default_root()
    assert root.is_dir()
    assert {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()} == {
        p.relative_to(BUNDLE).as_posix(): p.read_bytes() for p in BUNDLE.rglob('*') if p.is_file()}


@pytest.mark.parametrize('relative', [
    'README.md', 'AVAILABILITY.json', 'SOURCE-PROVENANCE.json',
    'fixtures/contracts/local-tool-event.v1.json',
    'schemas/service-profile.v1.schema.json',
    'manifests/video-knowledge-pipeline.agent-tool-manifest.v1.json',
    'contracts/evidence-bundle.v1.json',
    'proposals/registry-agent-tool-manifests.v1.json',
])
def test_referenced_byte_drift_blocks(relocated, relative):
    path = relocated / relative
    path.write_bytes(path.read_bytes()+b' ')
    with pytest.raises(integrity.CapsuleError, match=relative.replace('.', r'\.')):
        portable.verify(relocated)


@pytest.mark.parametrize('relative', ['../outside.json', '/outside.json', 'Z:/outside.json', r'\\server\outside.json'])
def test_escaping_artifact_path_blocks_before_read(relocated, relative):
    path = relocated / 'portable-contract-bundle.v1.json'; doc = read(path)
    doc['artifacts'][0]['path'] = relative; write(path, doc)
    with pytest.raises(integrity.CapsuleError) as error:
        portable.verify(relocated)
    assert error.value.code == 'BUNDLE_PATH_VIOLATION'


def test_duplicate_contract_id_blocks(relocated):
    path = relocated / 'portable-contract-bundle.v1.json'; doc = read(path)
    doc['contracts'][1]['contract_id'] = doc['contracts'][0]['contract_id']; write(path, doc)
    with pytest.raises(integrity.CapsuleError) as error: portable.verify(relocated)
    assert error.value.code == 'CONTRACT_SET_MISMATCH'


def test_resealed_wrapper_cannot_acquire_execution_authority(relocated):
    path = relocated / 'contracts/review-packet.v1.json'; doc = read(path)
    doc['executionAuthority'] = 'approved_execute'; write(path, doc); seal(relocated)
    with pytest.raises(integrity.CapsuleError) as error: portable.verify(relocated)
    assert error.value.code == 'BUNDLE_AUTHORITY_DRIFT'


def test_resealed_wrapper_cannot_silently_substitute_review_contract(relocated):
    path = relocated / 'contracts/review-packet.v1.json'; doc = read(path)
    doc['contract']['facade_mode'] = 'direct_canonical'; write(path, doc); seal(relocated)
    with pytest.raises(integrity.CapsuleError) as error: portable.verify(relocated)
    assert error.value.code == 'CONTRACT_CATALOG_DRIFT'


def test_resealed_proposal_cannot_add_an_installed_tool_claim(relocated):
    path = relocated / 'proposals/registry-agent-tool-manifests.v1.json'; doc = read(path)
    doc['tool_count'] += 1; write(path, doc); seal(relocated)
    with pytest.raises(integrity.CapsuleError) as error: portable.verify(relocated)
    assert error.value.code == 'PROPOSAL_SCOPE_DRIFT'


def test_resealed_availability_cannot_turn_missing_owner_into_runtime_success(relocated):
    path = relocated / 'AVAILABILITY.json'; doc = read(path)
    doc['review-packet.v1']['runtime'] = 'passed'; write(path, doc); seal(relocated)
    with pytest.raises(integrity.CapsuleError) as error: portable.verify(relocated)
    assert error.value.code == 'RUNTIME_CLAIM_DRIFT'


def test_resealed_catalog_requires_matching_source_provenance(relocated):
    path = relocated / 'SOURCE-PROVENANCE.json'; doc = read(path)
    doc['native_source_bindings'][0]['authority'] = 'frozen_consumer_copy'; write(path, doc); seal(relocated)
    with pytest.raises(integrity.CapsuleError) as error: portable.verify(relocated)
    assert error.value.code == 'SOURCE_PROVENANCE_DRIFT'


def test_resealed_synthetic_event_still_requires_valid_datetime(relocated):
    path = relocated / 'fixtures/contracts/local-tool-event.v1.json'; doc = read(path)
    doc['time'] = 'not-a-date'; write(path, doc); seal(relocated)
    with pytest.raises(integrity.CapsuleError) as error: portable.verify(relocated)
    assert error.value.code == 'SCHEMA_INVALID'


def test_public_consumer_schema_does_not_claim_native_review_ownership():
    doc = read(BUNDLE / 'contracts/review-packet.v1.json')['contract']
    source, = doc['authoritative_source']
    assert source['authority'] == 'frozen_consumer_copy'
    assert source['locator']['tool_id'] == 'content-creation-system'
    assert source['locator']['relative_path'] == 'schemas/review-intake.v0.2.schema.json'
    assert {row['status'] for row in doc['compatibility']} == {'blocked'}


def test_cli_missing_bundle_reports_blocked(tmp_path, capsys):
    assert portable.main(['--bundle-root', str(tmp_path / 'missing')]) == 2
    result = json.loads(capsys.readouterr().err)
    assert result['status'] == 'blocked'
    assert result['metadata_authorizes_execution'] is False
