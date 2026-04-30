from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Sequence

from ubinascii import unhexlify

from kv_vectors import EMPTY_256_HEX, RECORD_VECTORS


def _sha256(data: bytes) -> bytes:
    from trezor.crypto.hashlib import sha256

    return sha256(data).digest()


EMPTY = [b""] * 257
EMPTY[256] = unhexlify(EMPTY_256_HEX)
for _depth in range(255, -1, -1):
    EMPTY[_depth] = _sha256(b"kv-smt-node-v1" + EMPTY[_depth + 1] + EMPTY[_depth + 1])


def leaf_hash(leaf_key: bytes, leaf_value_hash: bytes) -> bytes:
    return _sha256(b"kv-smt-leaf-v1" + leaf_key + leaf_value_hash)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _sha256(b"kv-smt-node-v1" + left + right)


def _key_int(key: bytes) -> int:
    return int.from_bytes(key, "big")


def vector_records() -> list[tuple[str, str, bytes, bytes]]:
    return [
        (
            item["key"],
            item["value"],
            unhexlify(item["record_id_hex"]),
            unhexlify(item["record_commitment_hex"]),
        )
        for item in RECORD_VECTORS
    ]


def build_levels(
    leaves: "Sequence[tuple[bytes, bytes]]",
) -> dict[int, dict[int, bytes]]:
    levels = {
        256: {_key_int(leaf_key): leaf_hash(leaf_key, leaf_value_hash) for leaf_key, leaf_value_hash in leaves}
    }
    current = levels[256]
    for depth in range(255, -1, -1):
        parents: dict[int, bytes] = {}
        for prefix in {_leaf_key >> 1 for _leaf_key in current}:
            left_prefix = prefix << 1
            right_prefix = left_prefix | 1
            left = current.get(left_prefix, EMPTY[depth + 1])
            right = current.get(right_prefix, EMPTY[depth + 1])
            parents[prefix] = node_hash(left, right)
        levels[depth] = parents
        current = parents
    return levels


def root_for(leaves: "Sequence[tuple[bytes, bytes]]") -> bytes:
    return build_levels(leaves)[0].get(0, EMPTY[0])


def proof_for(leaves: "Sequence[tuple[bytes, bytes]]", leaf_key: bytes) -> list[bytes]:
    levels = build_levels(leaves)
    prefix = _key_int(leaf_key)
    siblings: list[bytes] = []
    for depth in range(256, 0, -1):
        siblings.append(levels[depth].get(prefix ^ 1, EMPTY[depth]))
        prefix >>= 1
    return siblings
