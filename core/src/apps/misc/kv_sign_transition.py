from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trezor.messages import KvHead, KvSignTransition, KvSignedTransition


async def kv_sign_transition(msg: KvSignTransition) -> KvSignedTransition:
    from trezor.messages import KvHead, KvSignedTransition
    from trezor.wire import DataError

    from apps.common import kv, kv_auth, kv_layout

    keychain = await kv_auth.get_kv_keychain()
    with keychain:
        sign_public_key = kv_auth.sign_public_key(keychain)
        sign_secret_key = kv_auth.sign_private_key(keychain)
        index_key = kv_auth.index_key(keychain)

        old_head = msg.old_head
        proof = msg.proof

        try:
            new_head_data = kv.validate_transition(
                public_key=sign_public_key,
                index_key=index_key,
                schema_version=old_head.schema_version,
                operation=msg.operation,
                old_head_seq=old_head.seq,
                old_head_root=old_head.records_root,
                old_head_prev_hash=old_head.prev_head_hash or b"",
                old_head_signature=old_head.signature or b"",
                key=msg.key,
                old_value=msg.old_value,
                new_value=msg.new_value,
                proof_exists=proof.exists,
                proof_leaf_key=proof.leaf_key,
                proof_leaf_hash=proof.leaf_hash,
                proof_sibling_hashes=proof.sibling_hashes,
                proof_sibling_bitmap=proof.sibling_bitmap,
                proposed_new_root=msg.proposed_new_root,
            )
        except ValueError as exc:
            raise DataError(str(exc))

        await kv_layout.confirm_transition(
            msg.operation,
            msg.key,
            msg.old_value,
            msg.new_value,
        )

        signature = kv.sign_head(
            sign_secret_key,
            new_head_data["schema_version"],
            new_head_data["seq"],
            new_head_data["records_root"],
            new_head_data["prev_head_hash"],
        )

    new_head = KvHead(
        schema_version=new_head_data["schema_version"],
        seq=new_head_data["seq"],
        records_root=new_head_data["records_root"],
        prev_head_hash=new_head_data["prev_head_hash"],
        signature=signature,
    )
    return KvSignedTransition(new_head=new_head)
