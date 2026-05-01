from trezor.enums import ButtonRequestType
from trezor.ui.layouts import confirm_properties

from . import kv


async def confirm_transition(
    operation: int,
    key: str,
    old_value: str | None,
    new_value: str | None,
) -> None:
    if operation == kv.OP_ADD:
        title = "Add entry"
        props = (
            ("Key", key, True),
            ("Value", new_value or "", True),
        )
    elif operation == kv.OP_UPDATE:
        title = "Update entry"
        props = (
            ("Key", key, True),
            ("Old value", old_value or "", True),
            ("New value", new_value or "", True),
        )
    elif operation == kv.OP_DELETE:
        title = "Delete entry"
        props = (
            ("Key", key, True),
            ("Value", old_value or "", True),
        )
    else:
        raise ValueError("Unknown KV operation")

    await confirm_properties(
        "kv_sign_transition",
        title,
        props,
        hold=True,
        br_code=ButtonRequestType.ProtectCall,
    )
