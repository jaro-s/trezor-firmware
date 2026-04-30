import hashlib
import hmac
import struct

import pytest
from ecdsa.curves import SECP256k1
from mnemonic import Mnemonic

from trezorlib import misc
from trezorlib.debuglink import DebugSession as Session
from trezorlib.tools import HARDENED_FLAG

from ...common import MNEMONIC12

KV_INDEX_PATH = [999999 | HARDENED_FLAG, 0 | HARDENED_FLAG, 1 | HARDENED_FLAG]
RECORD_ID_DOMAIN = b"kv-record-id-v1"


def _ckd_priv(parent_key: bytes, parent_chain_code: bytes, index: int) -> tuple[bytes, bytes]:
    data = b"\x00" + parent_key + struct.pack(">L", index)
    i64 = hmac.new(parent_chain_code, data, hashlib.sha512).digest()
    child_num = (int.from_bytes(i64[:32], "big") + int.from_bytes(parent_key, "big")) % SECP256k1.order
    return child_num.to_bytes(32, "big"), i64[32:]


def _index_key_from_mnemonic(mnemonic: str) -> bytes:
    seed = Mnemonic.to_seed(mnemonic, passphrase="")
    i64 = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key = i64[:32]
    chain_code = i64[32:]
    for index in KV_INDEX_PATH:
        key, chain_code = _ckd_priv(key, chain_code, index)
    return key


def _expected_record_id(mnemonic: str, key: str) -> bytes:
    digest = hmac.new(_index_key_from_mnemonic(mnemonic), RECORD_ID_DOMAIN, hashlib.sha256)
    digest.update(key.encode())
    return digest.digest()


@pytest.mark.setup_client(mnemonic=MNEMONIC12)
def test_get_kv_record_id(session: Session):
    response = misc.get_kv_record_id(session, "alice")
    assert response.record_id == _expected_record_id(MNEMONIC12, "alice")
