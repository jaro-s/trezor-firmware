from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trezor.messages import KvAuthority, KvGetAuthority


async def kv_get_authority(msg: KvGetAuthority) -> KvAuthority:
    from trezor.messages import KvAuthority

    from apps.common import kv, kv_auth

    keychain = await kv_auth.get_kv_keychain()
    with keychain:
        return KvAuthority(
            schema_version=kv.SCHEMA_VERSION,
            public_key=kv_auth.sign_public_key(keychain),
        )
