import types
import unittest

import pydantic
from zenith.sync import config
from zenith.sync.processor import helm


def session_storage_values(**valkey):
    """
    Returns the OAuth2 proxy session storage values for the given Valkey config.
    """
    oidc = config.OIDCConfig(valkey=config.OIDCValkeyConfig(**valkey))
    processor = types.SimpleNamespace(
        config=types.SimpleNamespace(ingress=types.SimpleNamespace(oidc=oidc))
    )
    return helm.Processor._get_oidc_session_storage_values(processor)


class TestOIDCSessionStorage(unittest.TestCase):
    def test_cookie_by_default(self):
        self.assertEqual(session_storage_values(), {"type": "cookie"})

    def test_valkey_without_password(self):
        self.assertEqual(
            session_storage_values(url="redis://valkey.zenith:6379"),
            {
                "type": "redis",
                "redis": {
                    "clientType": "standalone",
                    "standalone": {"connectionUrl": "redis://valkey.zenith:6379"},
                },
            },
        )

    def test_valkey_with_password_secret(self):
        values = session_storage_values(
            url="rediss://valkey.zenith:6379",
            password_secret_name="zenith-valkey-password",
        )
        self.assertEqual(values["redis"]["existingSecret"], "zenith-valkey-password")
        self.assertEqual(values["redis"]["passwordKey"], "password")

    def test_valkey_with_password_secret_key(self):
        values = session_storage_values(
            url="redis://valkey.zenith:6379",
            password_secret_name="zenith-valkey-password",
            password_secret_key="valkey-password",
        )
        self.assertEqual(values["redis"]["passwordKey"], "valkey-password")

    def test_valkey_url_requires_redis_scheme(self):
        with self.assertRaises(pydantic.ValidationError):
            config.OIDCValkeyConfig(url="http://valkey.zenith:6379")

    def test_valkey_config_accepts_camel_case(self):
        oidc = config.OIDCConfig.model_validate(
            {
                "valkey": {
                    "url": "redis://valkey.zenith:6379",
                    "passwordSecretName": "zenith-valkey-password",
                    "passwordSecretKey": "password",
                },
            }
        )
        self.assertEqual(oidc.valkey.password_secret_name, "zenith-valkey-password")
