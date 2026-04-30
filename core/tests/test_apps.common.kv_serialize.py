# flake8: noqa: F403,F405
from common import *  # isort:skip

from ubinascii import unhexlify

from kv_vectors import INDEX_KEY_HEX, RECORD_VECTORS

from apps.common import kv_serialize


class TestKvSerialize(unittest.TestCase):
    def test_serialize_record_vectors(self):
        for item in RECORD_VECTORS:
            self.assertEqual(
                kv_serialize.serialize_record(item["key"], item["value"]),
                unhexlify(item["serialized_hex"]),
            )

    def test_record_id_vectors(self):
        index_key = unhexlify(INDEX_KEY_HEX)
        for item in RECORD_VECTORS:
            self.assertEqual(
                kv_serialize.record_id(index_key, item["key"]),
                unhexlify(item["record_id_hex"]),
            )

    def test_record_commitment_vectors(self):
        for item in RECORD_VECTORS:
            self.assertEqual(
                kv_serialize.record_commitment(
                    unhexlify(item["record_id_hex"]), item["key"], item["value"]
                ),
                unhexlify(item["record_commitment_hex"]),
            )

    def test_validate_key_rejects_empty(self):
        with self.assertRaises(ValueError):
            kv_serialize.validate_key("")


if __name__ == "__main__":
    unittest.main()
