import pytest
from ecdsa.curves import SECP256k1
from ecdsa.util import number_to_string

from trezorlib import btc, misc
from trezorlib.debuglink import DebugSession as Session
from trezorlib.tools import parse_path

from ...bip32 import sec_to_public_pair
from ...common import MNEMONIC12

KV_SIGN_PATH = parse_path("m/999999h/0h/0h")


@pytest.mark.setup_client(mnemonic=MNEMONIC12)
def test_get_kv_authority(session: Session):
    compressed = btc.get_public_node(session, KV_SIGN_PATH).node.public_key
    x, y = sec_to_public_pair(compressed)
    expected = b"\x04" + number_to_string(x, SECP256k1.order) + number_to_string(
        y, SECP256k1.order
    )
    authority = misc.get_kv_authority(session)
    assert authority.schema_version == 1
    assert authority.public_key == expected
