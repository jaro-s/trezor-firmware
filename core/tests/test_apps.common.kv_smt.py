# flake8: noqa: F403,F405
from common import *  # isort:skip

from ubinascii import unhexlify

from kv_reference import proof_for, root_for, vector_records
from kv_vectors import (
    ABSENT_KEY,
    EMPTY_255_HEX,
    EMPTY_256_HEX,
    EMPTY_ROOT_HEX,
    INDEX_KEY_HEX,
    RECORD_VECTORS,
    ROOT_AFTER_1_HEX,
    ROOT_AFTER_2_HEX,
    ROOT_AFTER_3_HEX,
)

from apps.common import kv_serialize, kv_smt


class TestKvSmt(unittest.TestCase):
    def test_empty_hash_vectors(self):
        self.assertEqual(kv_smt.empty_hash(256), unhexlify(EMPTY_256_HEX))
        self.assertEqual(kv_smt.empty_hash(255), unhexlify(EMPTY_255_HEX))
        self.assertEqual(kv_smt.empty_root(), unhexlify(EMPTY_ROOT_HEX))

    def test_root_vectors(self):
        leaves = [(record_id, commitment) for _, _, record_id, commitment in vector_records()]
        self.assertEqual(root_for(leaves[:1]), unhexlify(ROOT_AFTER_1_HEX))
        self.assertEqual(root_for(leaves[:2]), unhexlify(ROOT_AFTER_2_HEX))
        self.assertEqual(root_for(leaves), unhexlify(ROOT_AFTER_3_HEX))

    def test_inclusion_proof_verification(self):
        leaves = [(record_id, commitment) for _, _, record_id, commitment in vector_records()]
        record = RECORD_VECTORS[1]
        leaf_key = unhexlify(record["record_id_hex"])
        leaf_hash = kv_smt.leaf_hash(leaf_key, unhexlify(record["record_commitment_hex"]))
        siblings = proof_for(leaves, leaf_key)
        self.assertEqual(
            kv_smt.compute_root_from_proof(leaf_key, True, leaf_hash, siblings),
            unhexlify(ROOT_AFTER_3_HEX),
        )

    def test_absence_proof_verification(self):
        index_key = unhexlify(INDEX_KEY_HEX)
        leaves = [(record_id, commitment) for _, _, record_id, commitment in vector_records()]
        leaf_key = kv_serialize.record_id(index_key, ABSENT_KEY)
        siblings = proof_for(leaves, leaf_key)
        self.assertEqual(
            kv_smt.compute_root_from_proof(leaf_key, False, None, siblings),
            unhexlify(ROOT_AFTER_3_HEX),
        )


if __name__ == "__main__":
    unittest.main()
