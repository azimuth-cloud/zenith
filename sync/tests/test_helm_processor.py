import logging
import unittest
from unittest import mock

from zenith.sync import config, model
from zenith.sync.processor import helm


def make_processor(**oidc):
    """
    Returns a processor with the given OIDC config, without connecting to Kubernetes.
    """
    processor = helm.Processor.__new__(helm.Processor)
    processor.config = config.KubernetesConfig(
        self_namespace="zenith",
        ingress=config.IngressConfig(
            base_domain="apps.example.com",
            oidc=config.OIDCConfig(discovery_enabled=True, **oidc),
        ),
    )
    processor.logger = logging.getLogger(__name__)
    processor._reconcile_oidc_credentials = mock.AsyncMock(
        return_value=("https://identity.example.com", "client-id", "secret", [])
    )
    processor._reconcile_oidc_cookie_secret = mock.AsyncMock(
        return_value="cookie-secret"
    )
    return processor


class TestOIDCProxyValues(unittest.IsolatedAsyncioTestCase):
    async def test_claims_are_injected_into_the_request(self):
        processor = make_processor(
            inject_request_headers={
                "X-Remote-User": "preferred_username",
                "X-Remote-Group": "groups",
            }
        )
        values = await processor._get_auth_values(model.Service(name="svc1"))
        config_data = values["oidc"]["alphaConfig"]["configData"]
        self.assertEqual(
            config_data["injectRequestHeaders"],
            [
                {"name": "X-Remote-User", "values": [{"claim": "preferred_username"}]},
                {"name": "X-Remote-Group", "values": [{"claim": "groups"}]},
            ],
        )
        self.assertNotIn("injectResponseHeaders", config_data)

    async def test_upstream_defaults(self):
        processor = make_processor()
        values = await processor._get_auth_values(model.Service(name="svc1"))
        self.assertEqual(
            values["oidc"]["upstream"], {"protocol": "http", "readTimeout": None}
        )

    async def test_upstream_matches_service(self):
        processor = make_processor()
        service = model.Service(
            name="svc1",
            config={"backend-protocol": "https", "read-timeout": "600"},
        )
        values = await processor._get_auth_values(service)
        self.assertEqual(
            values["oidc"]["upstream"], {"protocol": "https", "readTimeout": 600}
        )
        # The values for the service itself should agree
        service_values = processor._get_service_values(service)
        self.assertEqual(service_values["protocol"], "https")
        self.assertEqual(service_values["readTimeout"], 600)

    async def test_invalid_read_timeout_is_ignored(self):
        processor = make_processor()
        service = model.Service(name="svc1", config={"read-timeout": "ten"})
        values = await processor._get_auth_values(service)
        self.assertIsNone(values["oidc"]["upstream"]["readTimeout"])
        self.assertNotIn("readTimeout", processor._get_service_values(service))

    async def test_no_oidc_when_auth_skipped(self):
        processor = make_processor()
        service = model.Service(name="svc1", config={"skip-auth": True})
        values = await processor._get_auth_values(service)
        self.assertEqual(values["oidc"], {"enabled": False})
