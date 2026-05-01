from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from buffer_types import AnyBytes
    from typing import Sequence

from trezor.crypto.hashlib import sha256

HASH_SIZE = sha256.digest_size
TREE_DEPTH = HASH_SIZE * 8

_EMPTY_DOMAIN = b"kv-smt-empty-v1"
_LEAF_DOMAIN = b"kv-smt-leaf-v1"
_NODE_DOMAIN = b"kv-smt-node-v1"


def _sha256(data: bytes) -> bytes:
    return sha256(data).digest()


_EMPTY_HASHES = [b""] * (TREE_DEPTH + 1)
_EMPTY_HASHES[TREE_DEPTH] = _sha256(_EMPTY_DOMAIN + b"\xff")
for _depth in range(TREE_DEPTH - 1, -1, -1):
    _EMPTY_HASHES[_depth] = _sha256(
        _NODE_DOMAIN + _EMPTY_HASHES[_depth + 1] + _EMPTY_HASHES[_depth + 1]
    )
EMPTY_HASHES = tuple(_EMPTY_HASHES)
del _EMPTY_HASHES
del _depth


def empty_hash(depth: int) -> bytes:
    if not 0 <= depth <= TREE_DEPTH:
        raise ValueError("Invalid SMT depth")
    return EMPTY_HASHES[depth]


def empty_root() -> bytes:
    return EMPTY_HASHES[0]


def _validate_hash_len(value: AnyBytes, name: str) -> None:
    if len(value) != HASH_SIZE:
        raise ValueError(f"{name} must be {HASH_SIZE} bytes")


def leaf_hash(leaf_key: AnyBytes, leaf_value_hash: AnyBytes) -> bytes:
    _validate_hash_len(leaf_key, "leaf_key")
    _validate_hash_len(leaf_value_hash, "leaf_value_hash")
    return _sha256(_LEAF_DOMAIN + leaf_key + leaf_value_hash)


def node_hash(left: AnyBytes, right: AnyBytes) -> bytes:
    _validate_hash_len(left, "left")
    _validate_hash_len(right, "right")
    return _sha256(_NODE_DOMAIN + left + right)


def key_bit(leaf_key: AnyBytes, level: int) -> int:
    _validate_hash_len(leaf_key, "leaf_key")
    if not 0 <= level < TREE_DEPTH:
        raise ValueError("Invalid SMT level")
    byte = leaf_key[level // 8]
    shift = 7 - (level % 8)
    return (byte >> shift) & 1


def _bitmap_bit(bitmap: AnyBytes, index: int) -> int:
    byte = bitmap[index // 8]
    shift = 7 - (index % 8)
    return (byte >> shift) & 1


def compute_root_from_proof(
    leaf_key: AnyBytes,
    exists: bool,
    proof_leaf_hash: AnyBytes | None,
    sibling_hashes: "Sequence[AnyBytes]",
    sibling_bitmap: AnyBytes | None = None,
) -> bytes:
    _validate_hash_len(leaf_key, "leaf_key")
    bitmap_bytes = bytes(sibling_bitmap) if sibling_bitmap else b""
    compact = bool(bitmap_bytes)
    if compact:
        if len(bitmap_bytes) != HASH_SIZE:
            raise ValueError("Invalid sibling_bitmap length")
    elif len(sibling_hashes) != TREE_DEPTH:
        raise ValueError("Invalid sibling_hashes length")

    if exists:
        if proof_leaf_hash is None:
            raise ValueError("Inclusion proof requires leaf hash")
        current = bytes(proof_leaf_hash)
        _validate_hash_len(current, "proof_leaf_hash")
    else:
        if proof_leaf_hash is not None:
            raise ValueError("Absence proof must not include leaf hash")
        current = EMPTY_HASHES[TREE_DEPTH]

    sibling_index = 0
    for index in range(TREE_DEPTH):
        if compact:
            if _bitmap_bit(bitmap_bytes, index):
                if sibling_index >= len(sibling_hashes):
                    raise ValueError("Missing compact sibling hash")
                sibling_hash = bytes(sibling_hashes[sibling_index])
                _validate_hash_len(sibling_hash, "sibling")
                sibling_index += 1
            else:
                sibling_hash = EMPTY_HASHES[TREE_DEPTH - index]
        else:
            sibling_hash = bytes(sibling_hashes[index])
            _validate_hash_len(sibling_hash, "sibling")
        level = TREE_DEPTH - 1 - index
        if key_bit(leaf_key, level) == 0:
            current = node_hash(current, sibling_hash)
        else:
            current = node_hash(sibling_hash, current)

    if compact and sibling_index != len(sibling_hashes):
        raise ValueError("Unexpected extra compact sibling hashes")

    return current


def verify_proof(
    expected_root: AnyBytes,
    leaf_key: AnyBytes,
    exists: bool,
    proof_leaf_hash: AnyBytes | None,
    sibling_hashes: "Sequence[AnyBytes]",
    sibling_bitmap: AnyBytes | None = None,
) -> bool:
    _validate_hash_len(expected_root, "expected_root")
    return compute_root_from_proof(
        leaf_key, exists, proof_leaf_hash, sibling_hashes, sibling_bitmap
    ) == bytes(expected_root)
