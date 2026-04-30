# flake8: noqa: F403,F405
from common import *  # isort:skip

from ubinascii import unhexlify

from kv_reference import proof_for, vector_records
from kv_vectors import (
    EMPTY_ROOT_HEX,
    FIRST_SIGNED_HEAD_HASH_HEX,
    GENESIS_HEAD_HASH_HEX,
    INDEX_KEY_HEX,
    RECORD_VECTORS,
    ROOT_AFTER_1_HEX,
    ROOT_AFTER_3_HEX,
    ROOT_AFTER_DELETE_HEX,
    ROOT_AFTER_UPDATE_HEX,
    SIGN_SECRET_KEY_HEX,
)

from apps.common import kv, kv_serialize


class TestKv(unittest.TestCase):
    def test_head_hash_vectors(self):
        self.assertEqual(
            kv.head_hash(kv.SCHEMA_VERSION, 0, unhexlify(EMPTY_ROOT_HEX), b""),
            unhexlify(GENESIS_HEAD_HASH_HEX),
        )
        self.assertEqual(
            kv.head_hash(
                kv.SCHEMA_VERSION,
                1,
                unhexlify(ROOT_AFTER_1_HEX),
                unhexlify(GENESIS_HEAD_HASH_HEX),
            ),
            unhexlify(FIRST_SIGNED_HEAD_HASH_HEX),
        )

    def test_sign_and_verify_head(self):
        sign_secret_key = unhexlify(SIGN_SECRET_KEY_HEX)
        public_key = kv.public_key(sign_secret_key)
        signature = kv.sign_head(
            sign_secret_key,
            kv.SCHEMA_VERSION,
            1,
            unhexlify(ROOT_AFTER_1_HEX),
            unhexlify(GENESIS_HEAD_HASH_HEX),
        )
        self.assertTrue(
            kv.verify_head(
                public_key,
                kv.SCHEMA_VERSION,
                1,
                unhexlify(ROOT_AFTER_1_HEX),
                unhexlify(GENESIS_HEAD_HASH_HEX),
                signature,
            )
        )

    def test_validate_first_add_transition(self):
        sign_secret_key = unhexlify(SIGN_SECRET_KEY_HEX)
        public_key = kv.public_key(sign_secret_key)
        index_key = unhexlify(INDEX_KEY_HEX)
        record = RECORD_VECTORS[0]
        leaves = [
            (record_id, commitment)
            for _, _, record_id, commitment in vector_records()[:1]
        ]
        leaf_key = kv_serialize.record_id(index_key, record["key"])
        siblings = proof_for([], leaf_key)
        new_head = kv.create_signed_transition(
            sign_secret_key=sign_secret_key,
            public_key=public_key,
            index_key=index_key,
            schema_version=kv.SCHEMA_VERSION,
            operation=kv.OP_ADD,
            old_head_seq=0,
            old_head_root=unhexlify(EMPTY_ROOT_HEX),
            old_head_prev_hash=b"",
            old_head_signature=b"",
            key=record["key"],
            old_value=None,
            new_value=record["value"],
            proof_exists=False,
            proof_leaf_key=leaf_key,
            proof_leaf_hash=None,
            proof_sibling_hashes=siblings,
            proposed_new_root=unhexlify(ROOT_AFTER_1_HEX),
        )
        self.assertEqual(new_head["seq"], 1)
        self.assertEqual(new_head["records_root"], unhexlify(ROOT_AFTER_1_HEX))
        self.assertEqual(new_head["prev_head_hash"], unhexlify(GENESIS_HEAD_HASH_HEX))
        self.assertTrue(
            kv.verify_head(
                public_key,
                new_head["schema_version"],
                new_head["seq"],
                new_head["records_root"],
                new_head["prev_head_hash"],
                new_head["signature"],
            )
        )

    def test_validate_update_and_delete_transition(self):
        sign_secret_key = unhexlify(SIGN_SECRET_KEY_HEX)
        public_key = kv.public_key(sign_secret_key)
        index_key = unhexlify(INDEX_KEY_HEX)
        records = vector_records()
        leaves = [(record_id, commitment) for _, _, record_id, commitment in records]

        old_head_signature = kv.sign_head(
            sign_secret_key,
            kv.SCHEMA_VERSION,
            3,
            unhexlify(ROOT_AFTER_3_HEX),
            b"\x11" * 32,
        )

        # update
        update_record = RECORD_VECTORS[1]
        update_leaf_key = unhexlify(update_record["record_id_hex"])
        update_siblings = proof_for(leaves, update_leaf_key)
        update_leaf_hash = kv._record_leaf_hash(
            index_key, update_record["key"], update_record["value"]
        )[1]
        new_head = kv.create_signed_transition(
            sign_secret_key=sign_secret_key,
            public_key=public_key,
            index_key=index_key,
            schema_version=kv.SCHEMA_VERSION,
            operation=kv.OP_UPDATE,
            old_head_seq=3,
            old_head_root=unhexlify(ROOT_AFTER_3_HEX),
            old_head_prev_hash=b"\x11" * 32,
            old_head_signature=old_head_signature,
            key=update_record["key"],
            old_value=update_record["value"],
            new_value="value-2-updated",
            proof_exists=True,
            proof_leaf_key=update_leaf_key,
            proof_leaf_hash=update_leaf_hash,
            proof_sibling_hashes=update_siblings,
            proposed_new_root=unhexlify(ROOT_AFTER_UPDATE_HEX),
        )
        self.assertEqual(new_head["records_root"], unhexlify(ROOT_AFTER_UPDATE_HEX))

        # delete
        delete_record = RECORD_VECTORS[0]
        delete_leaf_key = unhexlify(delete_record["record_id_hex"])
        delete_siblings = proof_for(leaves, delete_leaf_key)
        delete_leaf_hash = kv._record_leaf_hash(
            index_key, delete_record["key"], delete_record["value"]
        )[1]
        delete_head = kv.create_signed_transition(
            sign_secret_key=sign_secret_key,
            public_key=public_key,
            index_key=index_key,
            schema_version=kv.SCHEMA_VERSION,
            operation=kv.OP_DELETE,
            old_head_seq=3,
            old_head_root=unhexlify(ROOT_AFTER_3_HEX),
            old_head_prev_hash=b"\x11" * 32,
            old_head_signature=old_head_signature,
            key=delete_record["key"],
            old_value=delete_record["value"],
            new_value=None,
            proof_exists=True,
            proof_leaf_key=delete_leaf_key,
            proof_leaf_hash=delete_leaf_hash,
            proof_sibling_hashes=delete_siblings,
            proposed_new_root=unhexlify(ROOT_AFTER_DELETE_HEX),
        )
        self.assertEqual(delete_head["records_root"], unhexlify(ROOT_AFTER_DELETE_HEX))


if __name__ == "__main__":
    unittest.main()
