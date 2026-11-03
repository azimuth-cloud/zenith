"""Test the Jinja templates that render the resources for each Client."""

from collections.abc import Callable
from typing import Any

import pytest
import yaml
from zenith.operator.config import settings
from zenith.operator.models import v1alpha1 as api
from zenith.operator.template import default_loader

MakeClient = Callable[..., api.Client]

BASIC = {"type": "Basic", "basic": {"secretName": "basic-creds"}}
BEARER = {"type": "Bearer", "bearer": {"secretName": "bearer-creds"}}
SERVICE_ACCOUNT = {
    "type": "ServiceAccount",
    "serviceAccount": {"clusterRoleName": "view"},
}
OIDC = {
    "oidc": {"issuer": "https://issuer.example.com", "credentialsSecretName": "oidc"}
}


def render(template: str, client: api.Client, **params: Any) -> dict[str, Any]:
    """Render a client template with the params the operator would pass."""
    params = {
        "name": "myclient",
        "namespace": "ns",
        "ssh_private_key_data": "a2V5",
        "upstream_host": "svc.ns.svc.cluster.local",
        "upstream_port": 8080,
        "config_checksum": "sum",
        "client": client,
        **params,
    }
    rendered: dict[str, Any] = default_loader.load(template, **params)
    return rendered


def client_config(client: api.Client) -> dict[str, Any]:
    """Render the client secret and return its parsed client.yaml."""
    secret = render("client/secret.yaml", client)
    config: dict[str, Any] = yaml.safe_load(secret["stringData"]["client.yaml"])
    return config


def pod_spec(deployment: dict[str, Any]) -> dict[str, Any]:
    """Return the pod spec of a rendered deployment."""
    spec: dict[str, Any] = deployment["spec"]["template"]["spec"]
    return spec


def containers(deployment: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return the containers of a rendered deployment keyed by name."""
    return {c["name"]: c for c in pod_spec(deployment)["containers"]}


def env(container: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return the env vars of a container keyed by name."""
    return {e["name"]: e for e in container.get("env", [])}


def secret_ref(name: str, key: str) -> dict[str, Any]:
    """Return an env var source that reads the given secret key."""
    return {"secretKeyRef": {"name": name, "key": key}}


def test_secret_defaults(make_client: MakeClient) -> None:
    """Check the client config rendered for a default client."""
    client = make_client()
    secret = render("client/secret.yaml", client)
    assert secret["metadata"]["name"] == "myclient-zenith-client"
    assert secret["metadata"]["labels"]["zenith.stackhpc.com/client"] == "myclient"
    assert client_config(client) == {
        "ssh_private_key_data": "a2V5",
        "server_address": "sshd.example.invalid",
        "server_port": 2222,
        "internal": False,
        "skip_auth": False,
        "auth_external_params": {},
        "forward_to_host": "svc.ns.svc.cluster.local",
        "forward_to_port": 8080,
        "backend_protocol": "http",
    }


def test_secret_flags(make_client: MakeClient) -> None:
    """Check that the debug, internal, skip-auth, scheme and OIDC options render."""
    config = client_config(
        make_client(
            debug=True,
            internal=True,
            auth={"skip": True, **OIDC},
            upstream={"serviceName": "svc", "scheme": "https"},
        )
    )
    assert config["debug"] is True
    assert config["internal"] is True
    assert config["skip_auth"] is True
    assert config["backend_protocol"] == "https"
    assert config["auth_oidc_issuer"].startswith("https://issuer.example.com")


def test_secret_merges_external_auth_params(
    make_client: MakeClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Check that external auth params are merged over the operator defaults.

    Operators set site-wide defaults that individual clients can override.
    """
    monkeypatch.setattr(
        settings, "default_external_auth_params", {"a": "default", "b": "default"}
    )
    client = make_client(auth={"external": {"params": {"b": "client", "c": "client"}}})
    assert client_config(client)["auth_external_params"] == {
        "a": "default",
        "b": "client",
        "c": "client",
    }


def test_secret_forwards_to_mitm_proxy(make_client: MakeClient) -> None:
    """
    Check that traffic goes to the MITM proxy over HTTP when it is enabled.

    The proxy injects the auth headers and handles TLS to the real upstream.
    """
    client = make_client(
        mitmProxy={"enabled": True, "port": 9090},
        upstream={"serviceName": "svc", "scheme": "https"},
    )
    config = client_config(client)
    assert config["forward_to_host"] == "127.0.0.1"
    assert config["forward_to_port"] == 9090
    assert config["backend_protocol"] == "http"


@pytest.mark.xfail(
    strict=True,
    reason="templates use upstream.read_timeout but the model field is readTimeout",
)
def test_secret_read_timeout(make_client: MakeClient) -> None:
    """Check that the upstream read timeout is rendered into the client config."""
    client = make_client(upstream={"serviceName": "svc", "readTimeout": 30})
    assert client_config(client)["read_timeout"] == 30


def test_deployment_defaults(make_client: MakeClient) -> None:
    """
    Check that a default client gets one container and a config checksum.

    The checksum annotation makes the pods restart when the client config changes.
    """
    deployment = render("client/deployment.yaml", make_client())
    assert deployment["metadata"]["name"] == "myclient-zenith-client"
    assert deployment["spec"]["replicas"] == 1
    annotations = deployment["spec"]["template"]["metadata"]["annotations"]
    assert annotations == {"zenith.stackhpc.com/config-checksum": "sum"}
    assert list(containers(deployment)) == ["zenith-client"]
    pod = pod_spec(deployment)
    for key in [
        "serviceAccountName",
        "imagePullSecrets",
        "nodeSelector",
        "affinity",
        "tolerations",
    ]:
        assert key not in pod


def test_deployment_pod_scheduling(make_client: MakeClient) -> None:
    """Check that replicas, pull secrets and scheduling options reach the pod."""
    client = make_client(
        replicaCount=3,
        imagePullSecrets=[{"name": "pull"}],
        nodeSelector={"disk": "ssd"},
        tolerations=[{"key": "k", "operator": "Exists"}],
        affinity={"nodeAffinity": {}},
    )
    deployment = render("client/deployment.yaml", client)
    pod = pod_spec(deployment)
    assert deployment["spec"]["replicas"] == 3
    assert pod["imagePullSecrets"] == [{"name": "pull"}]
    assert pod["nodeSelector"] == {"disk": "ssd"}
    assert pod["tolerations"] == [{"key": "k", "operator": "Exists"}]
    assert pod["affinity"] == {"nodeAffinity": {}}


def test_deployment_oidc_credentials(make_client: MakeClient) -> None:
    """Check that OIDC credentials are read from the referenced secret."""
    deployment = render("client/deployment.yaml", make_client(auth=OIDC))
    client_env = env(containers(deployment)["zenith-client"])
    assert client_env["ZENITH_CLIENT__AUTH_OIDC_CLIENT_ID"]["valueFrom"] == (
        secret_ref("oidc", "client-id")
    )
    assert client_env["ZENITH_CLIENT__AUTH_OIDC_CLIENT_SECRET"]["valueFrom"] == (
        secret_ref("oidc", "client-secret")
    )


def mitm_deployment(make_client: MakeClient, auth_inject: Any = None) -> dict[str, Any]:
    """Render an HTTPS client deployment with the MITM proxy enabled."""
    mitm: dict[str, Any] = {"enabled": True, "port": 9090}
    if auth_inject:
        mitm["authInject"] = auth_inject
    client = make_client(
        mitmProxy=mitm, upstream={"serviceName": "svc", "scheme": "https"}
    )
    return render("client/deployment.yaml", client, upstream_port=443)


def test_deployment_mitm_proxy(make_client: MakeClient) -> None:
    """Check that the MITM proxy sidecar forwards to the real upstream."""
    deployment = mitm_deployment(make_client)
    assert list(containers(deployment)) == ["zenith-client", "mitm-proxy"]
    proxy_env = env(containers(deployment)["mitm-proxy"])
    assert {k: v.get("value") for k, v in proxy_env.items()} == {
        "ZENITH_PROXY_LISTEN_PORT": "9090",
        "ZENITH_PROXY_UPSTREAM_SCHEME": "https",
        "ZENITH_PROXY_UPSTREAM_HOST": "svc.ns.svc.cluster.local",
        "ZENITH_PROXY_UPSTREAM_PORT": "443",
    }
    assert "serviceAccountName" not in pod_spec(deployment)


@pytest.mark.parametrize(
    ("auth_inject", "expected"),
    [
        (
            BASIC,
            {
                "ZENITH_PROXY_AUTH_INJECT": {"value": "basic"},
                "ZENITH_PROXY_AUTH_BASIC_USERNAME": {
                    "valueFrom": secret_ref("basic-creds", "username")
                },
                "ZENITH_PROXY_AUTH_BASIC_PASSWORD": {
                    "valueFrom": secret_ref("basic-creds", "password")
                },
            },
        ),
        (
            BEARER,
            {
                "ZENITH_PROXY_AUTH_INJECT": {"value": "bearer"},
                "ZENITH_PROXY_AUTH_BEARER_HEADER": {"value": "Authorization"},
                "ZENITH_PROXY_AUTH_BEARER_PREFIX": {"value": "Bearer"},
                "ZENITH_PROXY_AUTH_BEARER_TOKEN": {
                    "valueFrom": secret_ref("bearer-creds", "token")
                },
            },
        ),
    ],
    ids=["basic", "bearer"],
)
def test_deployment_mitm_proxy_auth_inject(
    make_client: MakeClient, auth_inject: Any, expected: dict[str, Any]
) -> None:
    """Check that the MITM proxy injects credentials from the referenced secret."""
    proxy_env = env(containers(mitm_deployment(make_client, auth_inject))["mitm-proxy"])
    for name, value in expected.items():
        assert {k: v for k, v in proxy_env[name].items() if k != "name"} == value


def test_deployment_mitm_proxy_service_account(make_client: MakeClient) -> None:
    """Check that ServiceAccount auth runs as the client's account with its token."""
    deployment = mitm_deployment(make_client, SERVICE_ACCOUNT)
    proxy_env = env(containers(deployment)["mitm-proxy"])
    assert proxy_env["ZENITH_PROXY_AUTH_INJECT"]["value"] == "bearer"
    assert proxy_env["ZENITH_PROXY_AUTH_BEARER_TOKEN_FILE"]["value"].endswith("/token")
    assert pod_spec(deployment)["serviceAccountName"] == "myclient-zenith-client"


def test_service_account_and_cluster_role_binding(make_client: MakeClient) -> None:
    """Check that the service account is bound to the requested cluster role."""
    client = make_client(mitmProxy={"enabled": True, "authInject": SERVICE_ACCOUNT})
    sa = render("client/serviceaccount.yaml", client)
    crb = render("client/clusterrolebinding.yaml", client)
    assert sa["metadata"]["name"] == "myclient-zenith-client"
    assert crb["metadata"]["name"] == "zenith-client:ns:myclient"
    assert crb["roleRef"]["name"] == "view"
    assert crb["subjects"] == [
        {"kind": "ServiceAccount", "namespace": "ns", "name": "myclient-zenith-client"}
    ]
