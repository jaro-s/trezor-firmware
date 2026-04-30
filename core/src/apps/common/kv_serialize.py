from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from buffer_types import AnyBytes

from trezor.crypto import hmac
from trezor.crypto.hashlib import sha256

from .writers import write_bytes_unchecked, write_compact_size

MAX_KEY_LENGTH = 256
MAX_VALUE_LENGTH = 4096

_RECORD_ID_DOMAIN = b"kv-record-id-v1"
_RECORD_COMMITMENT_DOMAIN = b"kv-record-v1"


def validate_key(key: str) -> bytes:
    key_bytes = key.encode()
    if not key_bytes:
        raise ValueError("KV key must not be empty")
    if len(key_bytes) > MAX_KEY_LENGTH:
        raise ValueError("KV key too long")
    return key_bytes


def validate_value(value: str) -> bytes:
    value_bytes = value.encode()
    if len(value_bytes) > MAX_VALUE_LENGTH:
        raise ValueError("KV value too long")
    return value_bytes


def serialize_record(key: str, value: str) -> bytes:
    key_bytes = validate_key(key)
    value_bytes = validate_value(value)

    buf = bytearray()
    write_compact_size(buf, len(key_bytes))
    write_bytes_unchecked(buf, key_bytes)
    write_compact_size(buf, len(value_bytes))
    write_bytes_unchecked(buf, value_bytes)
    return bytes(buf)


def record_id(index_key: AnyBytes, key: str) -> bytes:
    key_bytes = validate_key(key)
    digest = hmac(hmac.SHA256, index_key, _RECORD_ID_DOMAIN)
    digest.update(key_bytes)
    return digest.digest()


def record_commitment(record_id_bytes: AnyBytes, key: str, value: str) -> bytes:
    record_id_len = len(record_id_bytes)
    if record_id_len != sha256.digest_size:
        raise ValueError("Invalid record_id length")

    ctx = sha256()
    ctx.update(_RECORD_COMMITMENT_DOMAIN)
    ctx.update(record_id_bytes)
    ctx.update(serialize_record(key, value))
    return ctx.digest()
