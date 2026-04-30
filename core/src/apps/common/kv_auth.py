from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apps.common.keychain import Keychain

from trezor.crypto.curve import secp256k1

from apps.common.keychain import get_keychain
from apps.common.paths import AlwaysMatchingSchema, HARDENED

from . import kv_serialize

KV_ROOT_PATH = [999999 | HARDENED, 0 | HARDENED]
KV_SIGN_PATH = KV_ROOT_PATH + [0 | HARDENED]
KV_INDEX_PATH = KV_ROOT_PATH + [1 | HARDENED]


async def get_kv_keychain() -> "Keychain":
    return await get_keychain("secp256k1", [AlwaysMatchingSchema])


def sign_private_key(keychain: "Keychain") -> bytes:
    return keychain.derive(KV_SIGN_PATH).private_key()


def sign_public_key(keychain: "Keychain") -> bytes:
    return secp256k1.publickey(sign_private_key(keychain), False)


def index_key(keychain: "Keychain") -> bytes:
    return keychain.derive(KV_INDEX_PATH).private_key()


def record_id(keychain: "Keychain", key: str) -> bytes:
    return kv_serialize.record_id(index_key(keychain), key)
