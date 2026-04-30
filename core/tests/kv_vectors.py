INDEX_KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
SIGN_SECRET_KEY_HEX = (
    "0102030405060708090a0b0c0d0e0f10"
    "1112131415161718191a1b1c1d1e1f20"
)
SEED_HEX = (
    "c76c4ac4f4e4a00d6b274d5c39c700bb4a7ddc04fbc6f78e85ca75007b5b495f"
    "74a9043eeb77bdd53aa6fc3a0e31462270316fa04b8c19114c8798706cd02ac8"
)
DERIVED_SIGN_SECRET_KEY_HEX = (
    "f431da6f119281bad934ed944d4e6712"
    "c2ceab1a83b5fc538e8f31ec985a9d66"
)
DERIVED_SIGN_PUBLIC_KEY_HEX = (
    "042965c78ace35899801602ce85c3e6c6162f6efca73e2e0f2368b12396b532242"
    "cef2a07320c77fd986b798850c58aad301f29106de7e5687fba50ff3904e88a2"
)
DERIVED_INDEX_KEY_HEX = (
    "cf5808d52e8e6cc36ced1e856f579483"
    "79202b61f46ebe878f5d76dfa4e7c9c0"
)
DERIVED_RECORD_ID_VECTORS = (
    {
        "key": "alice",
        "record_id_hex": (
            "88767d87ba5af419959a84e239e75426"
            "3c605e201ec34d195fdba5da1fc53d45"
        ),
    },
    {
        "key": "bob",
        "record_id_hex": (
            "5a810badc9d2efb99c4a821cec1dc957"
            "cbdf384b8efd5fd465041da745f50a0d"
        ),
    },
    {
        "key": "řeřicha",
        "record_id_hex": (
            "480d509dd62651138e833e96b4b173ec"
            "a1a04b91e4cda241eef8651d703cf917"
        ),
    },
)

RECORD_VECTORS = (
    {
        "key": "alice",
        "value": "value-one",
        "serialized_hex": "05616c6963650976616c75652d6f6e65",
        "record_id_hex": (
            "ec4ebc38fd3694d4652b1a47d9143ffd"
            "029bee7422b1855062231d41689f9a78"
        ),
        "record_commitment_hex": (
            "400d740b38466fd49e53a07609441b01"
            "8c797685539ceaebf411a32bf95f449b"
        ),
    },
    {
        "key": "bob",
        "value": "value-two",
        "serialized_hex": "03626f620976616c75652d74776f",
        "record_id_hex": (
            "d1b39bcd9a5823be81c6c1779446a8fb"
            "2df556a9c7e71a278effeb214f7a98c6"
        ),
        "record_commitment_hex": (
            "f47bbf506eade9c62440ab23be6b7ee7"
            "c8c48b9d6fc2bdba59f02e7a6850f069"
        ),
    },
    {
        "key": "řeřicha",
        "value": "žluťoučký",
        "serialized_hex": "09c59965c599696368610dc5be6c75c5a56f75c48d6bc3bd",
        "record_id_hex": (
            "33d07626b1ead64023915fc137670103"
            "501cd138b4a91a524bca8ef90f4e8e64"
        ),
        "record_commitment_hex": (
            "b765eb2bac1f4e1d8d8deec92ad63098"
            "00a377b246f2d6071be66fb73902bd40"
        ),
    },
)

EMPTY_256_HEX = "84d7512edde463b6d3e52ff2660995260be1ebaa5eab17cf0b99623e93a1002d"
EMPTY_255_HEX = "290ca551276c49cd30e9a312adf473906abf96400f1b42abff08b9f6dab53c3f"
EMPTY_ROOT_HEX = "7b34914e92166af7b5cc746084ebae6c617a1d43714985281642e8be16e58ff9"

ROOT_AFTER_1_HEX = "6d388349e7fb0015524747c8986431a35cc617e66daec1a39e88b4670e8d6d5a"
ROOT_AFTER_2_HEX = "e16e1981f8943bbdf65df6a4cbc9956572c7e6644493b9a32631753a45351fc2"
ROOT_AFTER_3_HEX = "eb39a37f3ae05a923c8c61c9079a5320e8622eea5dee92fa52090773555d38b4"
ROOT_AFTER_UPDATE_HEX = "a7b61c0a012e89f4e8a4f95a7aa56067985313f50d3058ca26763e52f08f28eb"
ROOT_AFTER_DELETE_HEX = "2093c292fdca05733d7c53af3e9f5faac131f92c5077a9b0f7ff9de5109be4a1"

GENESIS_HEAD_HASH_HEX = "f13718f9055c42752f850c44424275c5ae217d9b7443c225594bf7eb34dcd59f"
FIRST_SIGNED_HEAD_HASH_HEX = "6e6ae6cc666a3f7ad886656a70de3969f728142aea690ef699904477ac120cff"

ABSENT_KEY = "carol"
