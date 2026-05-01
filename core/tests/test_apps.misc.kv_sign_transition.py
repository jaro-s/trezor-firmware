# flake8: noqa: F403,F405
from common import *  # isort:skip

from ubinascii import unhexlify

from trezor import wire

from kv_reference import root_for
from kv_vectors import (
    DERIVED_INDEX_KEY_HEX,
    DERIVED_SIGN_PUBLIC_KEY_HEX,
    RECORD_VECTORS,
    SEED_HEX,
)

import apps.common.keychain as keychain
import apps.common.kv_layout as kv_layout
from apps.common import kv, kv_smt, kv_serialize
from apps.common.keychain import Keychain
from apps.misc.kv_sign_transition import kv_sign_transition
from trezor.messages import KvHead, KvSignTransition, KvSparseMerkleProof

EMPTY_BITMAP = b"\x00" * 32


class TestKvSignTransition(unittest.TestCase):
    def setUp(self):
        self._orig_get_keychain = keychain.get_keychain
        self._orig_confirm_transition = kv_layout.confirm_transition
        seed = unhexlify(SEED_HEX)

        async def fake_get_keychain(curve, schemas, slip21_namespaces=()):
            return Keychain(seed, curve, schemas, slip21_namespaces)

        async def fake_confirm_transition(*args, **kwargs):
            return None

        keychain.get_keychain = fake_get_keychain
        kv_layout.confirm_transition = fake_confirm_transition
        self.index_key = unhexlify(DERIVED_INDEX_KEY_HEX)

    def tearDown(self):
        keychain.get_keychain = self._orig_get_keychain
        kv_layout.confirm_transition = self._orig_confirm_transition

    def _record_id(self, key: str) -> bytes:
        return kv_serialize.record_id(self.index_key, key)

    def _genesis_head(self) -> KvHead:
        return KvHead(
            schema_version=kv.SCHEMA_VERSION,
            seq=0,
            records_root=kv_smt.empty_root(),
            prev_head_hash=b"",
            signature=b"",
        )

    def test_sign_add_transition(self):
        record = RECORD_VECTORS[0]
        record_id = self._record_id(record["key"])
        commitment = kv_serialize.record_commitment(
            record_id, record["key"], record["value"]
        )
        add_root = root_for(((record_id, commitment),))

        response = await_result(
            kv_sign_transition(
                KvSignTransition(
                    operation=kv.OP_ADD,
                    key=record["key"],
                    old_head=self._genesis_head(),
                    new_value=record["value"],
                    proof=KvSparseMerkleProof(
                        leaf_key=record_id,
                        sibling_bitmap=EMPTY_BITMAP,
                        exists=False,
                    ),
                    proposed_new_root=add_root,
                )
            )
        )

        self.assertEqual(response.new_head.seq, 1)
        self.assertEqual(response.new_head.records_root, add_root)
        self.assertTrue(
            kv.verify_head(
                unhexlify(DERIVED_SIGN_PUBLIC_KEY_HEX),
                response.new_head.schema_version,
                response.new_head.seq,
                response.new_head.records_root,
                response.new_head.prev_head_hash or b"",
                response.new_head.signature,
            )
        )

    def test_sign_update_and_delete_transition(self):
        record = RECORD_VECTORS[0]
        record_id = self._record_id(record["key"])
        commitment = kv_serialize.record_commitment(
            record_id, record["key"], record["value"]
        )
        add_root = root_for(((record_id, commitment),))
        add_response = await_result(
            kv_sign_transition(
                KvSignTransition(
                    operation=kv.OP_ADD,
                    key=record["key"],
                    old_head=self._genesis_head(),
                    new_value=record["value"],
                    proof=KvSparseMerkleProof(
                        leaf_key=record_id,
                        sibling_bitmap=EMPTY_BITMAP,
                        exists=False,
                    ),
                    proposed_new_root=add_root,
                )
            )
        )

        old_leaf_hash = kv_smt.leaf_hash(record_id, commitment)
        update_value = "value-updated"
        updated_commitment = kv_serialize.record_commitment(
            record_id, record["key"], update_value
        )
        update_root = root_for(((record_id, updated_commitment),))
        update_response = await_result(
            kv_sign_transition(
                KvSignTransition(
                    operation=kv.OP_UPDATE,
                    key=record["key"],
                    old_head=add_response.new_head,
                    old_value=record["value"],
                    new_value=update_value,
                    proof=KvSparseMerkleProof(
                        leaf_key=record_id,
                        leaf_hash=old_leaf_hash,
                        sibling_bitmap=EMPTY_BITMAP,
                        exists=True,
                    ),
                    proposed_new_root=update_root,
                )
            )
        )
        self.assertEqual(update_response.new_head.seq, 2)
        self.assertEqual(update_response.new_head.records_root, update_root)

        updated_leaf_hash = kv_smt.leaf_hash(record_id, updated_commitment)
        delete_response = await_result(
            kv_sign_transition(
                KvSignTransition(
                    operation=kv.OP_DELETE,
                    key=record["key"],
                    old_head=update_response.new_head,
                    old_value=update_value,
                    proof=KvSparseMerkleProof(
                        leaf_key=record_id,
                        leaf_hash=updated_leaf_hash,
                        sibling_bitmap=EMPTY_BITMAP,
                        exists=True,
                    ),
                    proposed_new_root=kv_smt.empty_root(),
                )
            )
        )
        self.assertEqual(delete_response.new_head.seq, 3)
        self.assertEqual(delete_response.new_head.records_root, kv_smt.empty_root())

    def test_sign_transition_rejects_bad_signature(self):
        record = RECORD_VECTORS[0]
        record_id = self._record_id(record["key"])
        commitment = kv_serialize.record_commitment(
            record_id, record["key"], record["value"]
        )
        add_root = root_for(((record_id, commitment),))
        add_response = await_result(
            kv_sign_transition(
                KvSignTransition(
                    operation=kv.OP_ADD,
                    key=record["key"],
                    old_head=self._genesis_head(),
                    new_value=record["value"],
                    proof=KvSparseMerkleProof(
                        leaf_key=record_id,
                        sibling_bitmap=EMPTY_BITMAP,
                        exists=False,
                    ),
                    proposed_new_root=add_root,
                )
            )
        )

        bad_signature = add_response.new_head.signature[:-1] + b"\x00"
        with self.assertRaises(wire.DataError):
            await_result(
                kv_sign_transition(
                    KvSignTransition(
                        operation=kv.OP_UPDATE,
                        key=record["key"],
                        old_head=KvHead(
                            schema_version=add_response.new_head.schema_version,
                            seq=add_response.new_head.seq,
                            records_root=add_response.new_head.records_root,
                            prev_head_hash=add_response.new_head.prev_head_hash,
                            signature=bad_signature,
                        ),
                        old_value=record["value"],
                        new_value="next-value",
                        proof=KvSparseMerkleProof(
                            leaf_key=record_id,
                            leaf_hash=kv_smt.leaf_hash(record_id, commitment),
                            sibling_bitmap=EMPTY_BITMAP,
                            exists=True,
                        ),
                        proposed_new_root=root_for(
                            (
                                (
                                    record_id,
                                    kv_serialize.record_commitment(
                                        record_id, record["key"], "next-value"
                                    ),
                                ),
                            )
                        ),
                    )
                )
            )

    def test_sign_transition_user_rejection(self):
        async def reject_confirm(*args, **kwargs):
            raise wire.ActionCancelled()

        kv_layout.confirm_transition = reject_confirm

        record = RECORD_VECTORS[0]
        record_id = self._record_id(record["key"])
        commitment = kv_serialize.record_commitment(
            record_id, record["key"], record["value"]
        )
        with self.assertRaises(wire.ActionCancelled):
            await_result(
                kv_sign_transition(
                    KvSignTransition(
                        operation=kv.OP_ADD,
                        key=record["key"],
                        old_head=self._genesis_head(),
                        new_value=record["value"],
                        proof=KvSparseMerkleProof(
                            leaf_key=record_id,
                            sibling_bitmap=EMPTY_BITMAP,
                            exists=False,
                        ),
                        proposed_new_root=root_for(((record_id, commitment),)),
                    )
                )
            )


if __name__ == "__main__":
    unittest.main()
