# flake8: noqa: F403,F405
from common import *  # isort:skip

from ubinascii import unhexlify

from kv_vectors import DERIVED_SIGN_PUBLIC_KEY_HEX, SEED_HEX

import apps.common.keychain as keychain
from apps.common.keychain import Keychain
from apps.common.paths import AlwaysMatchingSchema
from apps.misc.kv_get_authority import kv_get_authority
from trezor.messages import KvGetAuthority


class TestKvGetAuthority(unittest.TestCase):
    def setUp(self):
        self._orig_get_keychain = keychain.get_keychain
        seed = unhexlify(SEED_HEX)

        async def fake_get_keychain(curve, schemas, slip21_namespaces=()):
            return Keychain(seed, curve, schemas, slip21_namespaces)

        keychain.get_keychain = fake_get_keychain

    def tearDown(self):
        keychain.get_keychain = self._orig_get_keychain

    def test_get_authority(self):
        response = await_result(kv_get_authority(KvGetAuthority()))
        self.assertEqual(response.schema_version, 1)
        self.assertEqual(response.public_key, unhexlify(DERIVED_SIGN_PUBLIC_KEY_HEX))


if __name__ == "__main__":
    unittest.main()
