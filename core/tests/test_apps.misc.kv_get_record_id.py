# flake8: noqa: F403,F405
from common import *  # isort:skip

from ubinascii import unhexlify

from kv_vectors import DERIVED_RECORD_ID_VECTORS, SEED_HEX

import apps.common.keychain as keychain
from apps.common.keychain import Keychain
from apps.common.paths import AlwaysMatchingSchema
from apps.misc.kv_get_record_id import kv_get_record_id
from trezor.messages import KvGetRecordId
from trezor.wire import DataError


class TestKvGetRecordId(unittest.TestCase):
    def setUp(self):
        self._orig_get_keychain = keychain.get_keychain
        seed = unhexlify(SEED_HEX)

        async def fake_get_keychain(curve, schemas, slip21_namespaces=()):
            return Keychain(seed, curve, schemas, slip21_namespaces)

        keychain.get_keychain = fake_get_keychain

    def tearDown(self):
        keychain.get_keychain = self._orig_get_keychain

    def test_get_record_id_vectors(self):
        for item in DERIVED_RECORD_ID_VECTORS:
            response = await_result(kv_get_record_id(KvGetRecordId(key=item["key"])))
            self.assertEqual(response.record_id, unhexlify(item["record_id_hex"]))

    def test_rejects_empty_key(self):
        with self.assertRaises(DataError):
            await_result(kv_get_record_id(KvGetRecordId(key="")))


if __name__ == "__main__":
    unittest.main()
