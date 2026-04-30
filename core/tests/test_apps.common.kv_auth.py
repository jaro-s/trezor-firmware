# flake8: noqa: F403,F405
from common import *  # isort:skip

from ubinascii import unhexlify

from kv_vectors import (
    DERIVED_INDEX_KEY_HEX,
    DERIVED_RECORD_ID_VECTORS,
    DERIVED_SIGN_PUBLIC_KEY_HEX,
    DERIVED_SIGN_SECRET_KEY_HEX,
    SEED_HEX,
)

from apps.common import kv_auth
from apps.common.keychain import Keychain
from apps.common.paths import AlwaysMatchingSchema


class TestKvAuth(unittest.TestCase):
    def test_derivation_vectors(self):
        keychain = Keychain(unhexlify(SEED_HEX), "secp256k1", [AlwaysMatchingSchema])
        self.assertEqual(
            kv_auth.sign_private_key(keychain),
            unhexlify(DERIVED_SIGN_SECRET_KEY_HEX),
        )
        self.assertEqual(
            kv_auth.sign_public_key(keychain),
            unhexlify(DERIVED_SIGN_PUBLIC_KEY_HEX),
        )
        self.assertEqual(kv_auth.index_key(keychain), unhexlify(DERIVED_INDEX_KEY_HEX))

    def test_record_id_vectors(self):
        keychain = Keychain(unhexlify(SEED_HEX), "secp256k1", [AlwaysMatchingSchema])
        for item in DERIVED_RECORD_ID_VECTORS:
            self.assertEqual(
                kv_auth.record_id(keychain, item["key"]),
                unhexlify(item["record_id_hex"]),
            )


if __name__ == "__main__":
    unittest.main()
