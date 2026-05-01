from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from buffer_types import AnyBytes
    from typing import Sequence

from trezor.crypto.curve import secp256k1
from trezor.crypto.hashlib import sha256

from . import kv_serialize, kv_smt
from .writers import (
    write_bytes_unchecked,
    write_compact_size,
    write_uint32_be,
    write_uint64_be,
)

SCHEMA_VERSION = 1

OP_ADD = 1
OP_UPDATE = 2
OP_DELETE = 3

_HEAD_DOMAIN = b"kv-head-v1"


def head_hash(
    schema_version: int,
    seq: int,
    records_root: AnyBytes,
    prev_head_hash: AnyBytes,
) -> bytes:
    if schema_version <= 0:
        raise ValueError("Invalid schema version")
    if seq < 0:
        raise ValueError("Invalid head sequence")
    kv_smt._validate_hash_len(records_root, "records_root")
    if prev_head_hash and len(prev_head_hash) != kv_smt.HASH_SIZE:
        raise ValueError("Invalid prev_head_hash length")

    buf = bytearray()
    write_bytes_unchecked(buf, _HEAD_DOMAIN)
    write_uint32_be(buf, schema_version)
    write_uint64_be(buf, seq)
    write_bytes_unchecked(buf, records_root)
    write_compact_size(buf, len(prev_head_hash))
    write_bytes_unchecked(buf, prev_head_hash)
    return sha256(buf).digest()


def public_key(sign_secret_key: AnyBytes) -> bytes:
    return secp256k1.publickey(sign_secret_key, False)


def sign_head(
    sign_secret_key: AnyBytes,
    schema_version: int,
    seq: int,
    records_root: AnyBytes,
    prev_head_hash: AnyBytes,
) -> bytes:
    return secp256k1.sign(
        sign_secret_key, head_hash(schema_version, seq, records_root, prev_head_hash)
    )


def verify_head(
    public_key_bytes: AnyBytes,
    schema_version: int,
    seq: int,
    records_root: AnyBytes,
    prev_head_hash: AnyBytes,
    signature: AnyBytes,
) -> bool:
    return secp256k1.verify(
        public_key_bytes,
        signature,
        head_hash(schema_version, seq, records_root, prev_head_hash),
    )


def is_canonical_genesis_head(
    schema_version: int,
    seq: int,
    records_root: AnyBytes,
    prev_head_hash: AnyBytes,
    signature: AnyBytes,
) -> bool:
    return (
        schema_version == SCHEMA_VERSION
        and seq == 0
        and bytes(records_root) == kv_smt.empty_root()
        and not prev_head_hash
        and not signature
    )


def _record_leaf_hash(index_key: AnyBytes, key: str, value: str) -> tuple[bytes, bytes]:
    record_id = kv_serialize.record_id(index_key, key)
    commitment = kv_serialize.record_commitment(record_id, key, value)
    return record_id, kv_smt.leaf_hash(record_id, commitment)


def validate_transition(
    *,
    public_key: AnyBytes,
    index_key: AnyBytes,
    schema_version: int,
    operation: int,
    old_head_seq: int,
    old_head_root: AnyBytes,
    old_head_prev_hash: AnyBytes,
    old_head_signature: AnyBytes,
    key: str,
    old_value: str | None,
    new_value: str | None,
    proof_exists: bool,
    proof_leaf_key: AnyBytes,
    proof_leaf_hash: AnyBytes | None,
    proof_sibling_hashes: "Sequence[AnyBytes]",
    proof_sibling_bitmap: AnyBytes | None = None,
    proposed_new_root: AnyBytes,
) -> dict[str, bytes | int]:
    if schema_version != SCHEMA_VERSION:
        raise ValueError("Unsupported schema version")

    is_genesis = is_canonical_genesis_head(
        schema_version,
        old_head_seq,
        old_head_root,
        old_head_prev_hash,
        old_head_signature,
    )
    if is_genesis:
        if operation != OP_ADD:
            raise ValueError("Genesis head only supports add")
    elif not verify_head(
        public_key,
        schema_version,
        old_head_seq,
        old_head_root,
        old_head_prev_hash,
        old_head_signature,
    ):
        raise ValueError("Invalid old head signature")

    expected_leaf_key = kv_serialize.record_id(index_key, key)
    if bytes(proof_leaf_key) != expected_leaf_key:
        raise ValueError("Proof leaf key mismatch")

    old_leaf_hash: bytes | None = None
    new_leaf_hash: bytes | None = None
    proof_leaf_hash_bytes = bytes(proof_leaf_hash) if proof_leaf_hash is not None else None

    if operation == OP_ADD:
        if old_value is not None or new_value is None or proof_exists:
            raise ValueError("Invalid add transition")
        if proof_leaf_hash_bytes is not None:
            raise ValueError("Absence proof must not include leaf hash")
        _, new_leaf_hash = _record_leaf_hash(index_key, key, new_value)
    elif operation == OP_UPDATE:
        if old_value is None or new_value is None or not proof_exists:
            raise ValueError("Invalid update transition")
        _, old_leaf_hash = _record_leaf_hash(index_key, key, old_value)
        _, new_leaf_hash = _record_leaf_hash(index_key, key, new_value)
    elif operation == OP_DELETE:
        if old_value is None or new_value is not None or not proof_exists:
            raise ValueError("Invalid delete transition")
        _, old_leaf_hash = _record_leaf_hash(index_key, key, old_value)
    else:
        raise ValueError("Unknown KV operation")

    if old_leaf_hash != proof_leaf_hash_bytes:
        raise ValueError("Proof leaf hash mismatch")

    if (
        kv_smt.compute_root_from_proof(
            proof_leaf_key,
            proof_exists,
            old_leaf_hash,
            proof_sibling_hashes,
            proof_sibling_bitmap,
        )
        != bytes(old_head_root)
    ):
        raise ValueError("Old proof does not match old root")

    new_root = kv_smt.compute_root_from_proof(
        proof_leaf_key,
        new_leaf_hash is not None,
        new_leaf_hash,
        proof_sibling_hashes,
        proof_sibling_bitmap,
    )
    if new_root != bytes(proposed_new_root):
        raise ValueError("Proposed new root mismatch")

    previous_head_hash = head_hash(
        schema_version, old_head_seq, old_head_root, old_head_prev_hash
    )
    new_head_seq = old_head_seq + 1
    return {
        "schema_version": schema_version,
        "seq": new_head_seq,
        "records_root": new_root,
        "prev_head_hash": previous_head_hash,
    }


def create_signed_transition(
    *,
    sign_secret_key: AnyBytes,
    public_key: AnyBytes,
    index_key: AnyBytes,
    schema_version: int,
    operation: int,
    old_head_seq: int,
    old_head_root: AnyBytes,
    old_head_prev_hash: AnyBytes,
    old_head_signature: AnyBytes,
    key: str,
    old_value: str | None,
    new_value: str | None,
    proof_exists: bool,
    proof_leaf_key: AnyBytes,
    proof_leaf_hash: AnyBytes | None,
    proof_sibling_hashes: "Sequence[AnyBytes]",
    proof_sibling_bitmap: AnyBytes | None = None,
    proposed_new_root: AnyBytes,
) -> dict[str, bytes | int]:
    new_head = validate_transition(
        public_key=public_key,
        index_key=index_key,
        schema_version=schema_version,
        operation=operation,
        old_head_seq=old_head_seq,
        old_head_root=old_head_root,
        old_head_prev_hash=old_head_prev_hash,
        old_head_signature=old_head_signature,
        key=key,
        old_value=old_value,
        new_value=new_value,
        proof_exists=proof_exists,
        proof_leaf_key=proof_leaf_key,
        proof_leaf_hash=proof_leaf_hash,
        proof_sibling_hashes=proof_sibling_hashes,
        proof_sibling_bitmap=proof_sibling_bitmap,
        proposed_new_root=proposed_new_root,
    )
    signature = sign_head(
        sign_secret_key,
        schema_version,
        new_head["seq"],
        new_head["records_root"],
        new_head["prev_head_hash"],
    )
    new_head["signature"] = signature
    return new_head


def verify_record(
    *,
    public_key: AnyBytes,
    index_key: AnyBytes,
    schema_version: int,
    seq: int,
    records_root: AnyBytes,
    prev_head_hash: AnyBytes,
    signature: AnyBytes,
    key: str,
    value: str,
    proof_exists: bool,
    proof_leaf_key: AnyBytes,
    proof_leaf_hash: AnyBytes | None,
    proof_sibling_hashes: "Sequence[AnyBytes]",
    proof_sibling_bitmap: AnyBytes | None = None,
) -> bool:
    if not verify_head(
        public_key,
        schema_version,
        seq,
        records_root,
        prev_head_hash,
        signature,
    ):
        return False

    if not proof_exists:
        return False

    record_id, leaf_hash = _record_leaf_hash(index_key, key, value)
    if bytes(proof_leaf_key) != record_id:
        return False
    if bytes(proof_leaf_hash or b"") != leaf_hash:
        return False

    return kv_smt.verify_proof(
        records_root,
        proof_leaf_key,
        True,
        leaf_hash,
        proof_sibling_hashes,
        proof_sibling_bitmap,
    )
