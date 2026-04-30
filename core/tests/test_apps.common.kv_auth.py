# flake8: noqa: F403,F405
from common import *  # isort:skip

from ubinascii import unhexlify

from kv_vectors import (
    KV_AUTH_DERIVATION_VECTORS,
    KV_AUTH_MAX_KEY,
)

from apps.common import kv_auth
from apps.common.keychain import Keychain
from apps.common.paths import AlwaysMatchingSchema


class TestKvAuth(unittest.TestCase):
    def _keychain(self, seed_hex):
        return Keychain(unhexlify(seed_hex), "secp256k1", [AlwaysMatchingSchema])

    def test_derivation_vectors(self):
        for item in KV_AUTH_DERIVATION_VECTORS:
            keychain = self._keychain(item["seed_hex"])
            sign_private_key = kv_auth.sign_private_key(keychain)
            index_key = kv_auth.index_key(keychain)
            self.assertEqual(sign_private_key, unhexlify(item["sign_secret_key_hex"]))
            self.assertEqual(
                kv_auth.sign_public_key(keychain),
                unhexlify(item["sign_public_key_hex"]),
            )
            self.assertEqual(index_key, unhexlify(item["index_key_hex"]))
            self.assertNotEqual(sign_private_key, index_key)

    def test_record_id_vectors(self):
        for derivation in KV_AUTH_DERIVATION_VECTORS:
            keychain = self._keychain(derivation["seed_hex"])
            for item in derivation["record_id_vectors"]:
                self.assertEqual(
                    kv_auth.record_id(keychain, item["key"]),
                    unhexlify(item["record_id_hex"]),
                )

    def test_record_id_rejects_invalid_keys(self):
        keychain = self._keychain(KV_AUTH_DERIVATION_VECTORS[0]["seed_hex"])
        with self.assertRaises(ValueError):
            kv_auth.record_id(keychain, "")
        with self.assertRaises(ValueError):
            kv_auth.record_id(keychain, KV_AUTH_MAX_KEY + "a")


if __name__ == "__main__":
    unittest.main()
