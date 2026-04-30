from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trezor.messages import KvGetRecordId, KvRecordId


async def kv_get_record_id(msg: KvGetRecordId) -> KvRecordId:
    from trezor.messages import KvRecordId
    from trezor.wire import DataError

    from apps.common import kv_auth

    keychain = await kv_auth.get_kv_keychain()
    with keychain:
        try:
            record_id = kv_auth.record_id(keychain, msg.key)
        except ValueError as exc:
            raise DataError(str(exc))

    return KvRecordId(record_id=record_id)
