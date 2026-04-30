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

KV_AUTH_MAX_KEY = "a" * 256

KV_AUTH_DERIVATION_VECTORS = (
    {
        "seed_hex": "000102030405060708090a0b0c0d0e0f",
        "sign_secret_key_hex": (
            "6e9fea9bd0b87f05b8a0092f649812b1"
            "cc0e5acfd7968d9b23fb015b7c65db27"
        ),
        "sign_public_key_hex": (
            "04576283eae1bc0cfd5ce64b845525e503554c5937f0d68a2099a1e15b445af6ff"
            "9fc0b75ffd289795a94be63b5e1f421efd507396e2e4ad15d08d7084eefc4712"
        ),
        "index_key_hex": (
            "85a1a95c237ee26bcf9181e28f1b4b52"
            "a27b8439579f7b7afaf5648f0499a4a7"
        ),
        "record_id_vectors": (
            {
                "key": "alice",
                "record_id_hex": (
                    "df83778de4d7d3f9c534c6979c037509"
                    "5d79f4dd7fda4db482bf42886626831a"
                ),
            },
            {
                "key": "bob",
                "record_id_hex": (
                    "1242192d5977b1e3214f36e7383bb012"
                    "12b73cfb8ad66c082bcd78e2b530d4e4"
                ),
            },
            {
                "key": "řeřicha",
                "record_id_hex": (
                    "011fe7a099e86918d8ee29cfc3e253fd"
                    "4e13310b6d0d5f59546c9c0b7394c9b2"
                ),
            },
            {
                "key": KV_AUTH_MAX_KEY,
                "record_id_hex": (
                    "70421847e5253c6c6dcfe37368e8d1d6"
                    "f39adc657dfa297a079575013220c7a4"
                ),
            },
        ),
    },
    {
        "seed_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "sign_secret_key_hex": (
            "a73a0919fde2d5814d9877b1d0fabb55"
            "6240a04f6da77c9d1d182b08c8fc9a76"
        ),
        "sign_public_key_hex": (
            "04b06fef4083a001bcdf98eccd9e327f7e39b0d30608578ab576b326fde8e3be69"
            "eb59ace72dcbac00c5ed304aa3bb8dd63e3d5c675aff9b722f929f4be04052f8"
        ),
        "index_key_hex": (
            "39e06994bbbc786aa5148f9455e43c18"
            "18607b6984188dc6af99984f3b34804d"
        ),
        "record_id_vectors": (
            {
                "key": "alice",
                "record_id_hex": (
                    "ce139ad0fc18e193558cfeea78037bdb"
                    "27e64effc0a7a6fda6bdb7a693e471f3"
                ),
            },
            {
                "key": "bob",
                "record_id_hex": (
                    "6d0dc2275364751bd884c93125fb3069"
                    "c5544a3eb88e7422cb65487dbdcdbfa5"
                ),
            },
            {
                "key": "řeřicha",
                "record_id_hex": (
                    "b26e837586748401651010b6dbb67e4c"
                    "f6f91ebfd0af6ab5e2153e28e676488a"
                ),
            },
            {
                "key": KV_AUTH_MAX_KEY,
                "record_id_hex": (
                    "14c8bbf0ef88acd52ae19fb7dd691031"
                    "6854acc57d12002d3e35df980c454c0b"
                ),
            },
        ),
    },
    {
        "seed_hex": SEED_HEX,
        "sign_secret_key_hex": DERIVED_SIGN_SECRET_KEY_HEX,
        "sign_public_key_hex": DERIVED_SIGN_PUBLIC_KEY_HEX,
        "index_key_hex": DERIVED_INDEX_KEY_HEX,
        "record_id_vectors": DERIVED_RECORD_ID_VECTORS
        + (
            {
                "key": KV_AUTH_MAX_KEY,
                "record_id_hex": (
                    "8aabcbed1136e6f676e97e0b322cf535"
                    "699d124b813f335b6719cc890a78ceb4"
                ),
            },
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
