import hashlib
from struct import pack

import pytest
from ecdsa import SECP256k1, VerifyingKey, util

from trezorlib import messages, misc
from trezorlib.debuglink import DebugSession as Session
from trezorlib.exceptions import Cancelled, TrezorFailure

from ...common import MNEMONIC12
from ...input_flows import InputFlowConfirmAllWarnings

HASH_SIZE = 32
TREE_DEPTH = 256
EMPTY_DOMAIN = b"kv-smt-empty-v1"
LEAF_DOMAIN = b"kv-smt-leaf-v1"
NODE_DOMAIN = b"kv-smt-node-v1"
HEAD_DOMAIN = b"kv-head-v1"
RECORD_DOMAIN = b"kv-record-v1"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _empty_hashes() -> list[bytes]:
    hashes = [b""] * (TREE_DEPTH + 1)
    hashes[TREE_DEPTH] = _sha256(EMPTY_DOMAIN + b"\xff")
    for depth in range(TREE_DEPTH - 1, -1, -1):
        hashes[depth] = _sha256(NODE_DOMAIN + hashes[depth + 1] + hashes[depth + 1])
    return hashes


EMPTY_HASHES = _empty_hashes()


def _serialize_record(key: str, value: str) -> bytes:
    key_bytes = key.encode()
    value_bytes = value.encode()
    return bytes([len(key_bytes)]) + key_bytes + bytes([len(value_bytes)]) + value_bytes


def _record_commitment(record_id: bytes, key: str, value: str) -> bytes:
    return _sha256(RECORD_DOMAIN + record_id + _serialize_record(key, value))


def _leaf_hash(leaf_key: bytes, leaf_value_hash: bytes) -> bytes:
    return _sha256(LEAF_DOMAIN + leaf_key + leaf_value_hash)


def _node_hash(left: bytes, right: bytes) -> bytes:
    return _sha256(NODE_DOMAIN + left + right)


def _key_bit(leaf_key: bytes, level: int) -> int:
    byte = leaf_key[level // 8]
    shift = 7 - (level % 8)
    return (byte >> shift) & 1


def _compute_root_from_proof(
    leaf_key: bytes,
    exists: bool,
    proof_leaf_hash: bytes | None,
    sibling_hashes: list[bytes],
    sibling_bitmap: bytes | None = None,
) -> bytes:
    compact = bool(sibling_bitmap)
    if exists:
        assert proof_leaf_hash is not None
        current = proof_leaf_hash
    else:
        assert proof_leaf_hash is None
        current = EMPTY_HASHES[TREE_DEPTH]

    sibling_index = 0
    for index in range(TREE_DEPTH):
        if compact:
            assert sibling_bitmap is not None
            byte = sibling_bitmap[index // 8]
            shift = 7 - (index % 8)
            if (byte >> shift) & 1:
                sibling_hash = sibling_hashes[sibling_index]
                sibling_index += 1
            else:
                sibling_hash = EMPTY_HASHES[TREE_DEPTH - index]
        else:
            sibling_hash = sibling_hashes[index]
        level = TREE_DEPTH - 1 - index
        if _key_bit(leaf_key, level) == 0:
            current = _node_hash(current, sibling_hash)
        else:
            current = _node_hash(sibling_hash, current)
    return current


EMPTY_BITMAP = b"\x00" * 32


def _head_hash(
    schema_version: int, seq: int, records_root: bytes, prev_head_hash: bytes
) -> bytes:
    return _sha256(
        HEAD_DOMAIN
        + pack(">I", schema_version)
        + pack(">Q", seq)
        + records_root
        + bytes([len(prev_head_hash)])
        + prev_head_hash
    )


def _verify_head_signature(public_key: bytes, signature: bytes, digest: bytes) -> bool:
    vk = VerifyingKey.from_string(public_key[1:], curve=SECP256k1)
    return vk.verify_digest(signature[1:], digest, sigdecode=util.sigdecode_string)


@pytest.mark.setup_client(mnemonic=MNEMONIC12)
def test_sign_kv_add_transition(session: Session):
    key = "alice"
    value = "value-one"
    record_id = misc.get_kv_record_id(session, key).record_id
    commitment = _record_commitment(record_id, key, value)
    leaf_hash = _leaf_hash(record_id, commitment)
    new_root = _compute_root_from_proof(
        record_id, True, leaf_hash, [], sibling_bitmap=EMPTY_BITMAP
    )
    empty_root = EMPTY_HASHES[0]
    old_head = messages.KvHead(
        schema_version=1,
        seq=0,
        records_root=empty_root,
        prev_head_hash=b"",
        signature=b"",
    )
    proof = messages.KvSparseMerkleProof(
        leaf_key=record_id,
        sibling_hashes=[],
        sibling_bitmap=EMPTY_BITMAP,
        exists=False,
    )

    with session.test_ctx as client:
        client.set_input_flow(InputFlowConfirmAllWarnings(client).get())
        response = misc.sign_kv_transition(
            session,
            messages.KvOperationType.Add,
            key,
            old_head,
            proof,
            new_root,
            new_value=value,
        )

    assert response.new_head.schema_version == 1
    assert response.new_head.seq == 1
    assert response.new_head.records_root == new_root

    genesis_hash = _head_hash(1, 0, empty_root, b"")
    assert response.new_head.prev_head_hash == genesis_hash

    authority = misc.get_kv_authority(session)
    digest = _head_hash(
        response.new_head.schema_version,
        response.new_head.seq,
        response.new_head.records_root,
        response.new_head.prev_head_hash,
    )
    assert _verify_head_signature(authority.public_key, response.new_head.signature, digest)


@pytest.mark.setup_client(mnemonic=MNEMONIC12)
def test_cancel_sign_kv_add_transition(session: Session):
    key = "alice"
    value = "value-one"
    record_id = misc.get_kv_record_id(session, key).record_id
    commitment = _record_commitment(record_id, key, value)
    leaf_hash = _leaf_hash(record_id, commitment)
    new_root = _compute_root_from_proof(
        record_id, True, leaf_hash, [], sibling_bitmap=EMPTY_BITMAP
    )
    old_head = messages.KvHead(
        schema_version=1,
        seq=0,
        records_root=EMPTY_HASHES[0],
        prev_head_hash=b"",
        signature=b"",
    )
    proof = messages.KvSparseMerkleProof(
        leaf_key=record_id,
        sibling_hashes=[],
        sibling_bitmap=EMPTY_BITMAP,
        exists=False,
    )

    def input_flow():
        yield
        session.debug.press_no()

    with pytest.raises(Cancelled), session.test_ctx as client:
        client.set_input_flow(input_flow)
        misc.sign_kv_transition(
            session,
            messages.KvOperationType.Add,
            key,
            old_head,
            proof,
            new_root,
            new_value=value,
        )


@pytest.mark.setup_client(mnemonic=MNEMONIC12)
def test_sign_kv_add_transition_rejects_invalid_proof(session: Session):
    key = "alice"
    value = "value-one"
    record_id = misc.get_kv_record_id(session, key).record_id
    bad_record_id = record_id[:-1] + bytes([record_id[-1] ^ 1])
    commitment = _record_commitment(record_id, key, value)
    leaf_hash = _leaf_hash(record_id, commitment)
    new_root = _compute_root_from_proof(
        record_id, True, leaf_hash, [], sibling_bitmap=EMPTY_BITMAP
    )
    old_head = messages.KvHead(
        schema_version=1,
        seq=0,
        records_root=EMPTY_HASHES[0],
        prev_head_hash=b"",
        signature=b"",
    )
    proof = messages.KvSparseMerkleProof(
        leaf_key=bad_record_id,
        sibling_hashes=[],
        sibling_bitmap=EMPTY_BITMAP,
        exists=False,
    )

    with pytest.raises(TrezorFailure, match="Proof leaf key mismatch"):
        misc.sign_kv_transition(
            session,
            messages.KvOperationType.Add,
            key,
            old_head,
            proof,
            new_root,
            new_value=value,
        )
