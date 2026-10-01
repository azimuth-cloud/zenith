"""
Tests for the Jinja templates that render per-Client resources.
"""

import pytest
import yaml
from zenith.operator.template import default_loader

from .helpers import make_client

BASIC = {"type": "Basic", "basic": {"secretName": "basic-creds"}}
BEARER = {"type": "Bearer", "bearer": {"secretName": "bearer-creds"}}
SERVICE_ACCOUNT = {
    "type": "ServiceAccount",
    "serviceAccount": {"clusterRoleName": "view"},
}


def render(template, client=None, **params):
    """
    Render a client template with sensible default params.
    """
    params = {
        "name": "myclient",
        "namespace": "ns",
        "ssh_private_key_data": "a2V5",
        "upstream_host": "svc.ns.svc.cluster.local",
        "upstream_port": 8080,
        "client": client or make_client(),
        **params,
    }
    return default_loader.load(template, **params)


def client_config(client=None):
    """
    Render the client secret and return its parsed client.yaml.
    """
    secret = render("client/secret.yaml", client)
    return yaml.safe_load(secret["stringData"]["client.yaml"])


def containers(deployment):
    """
    Return the containers of a rendered deployment keyed by name.
    """
    return {c["name"]: c for c in deployment["spec"]["template"]["spec"]["containers"]}


def env(container):
    """
    Return the env vars of a container keyed by name.
    """
    return {e["name"]: e for e in container.get("env", [])}


def test_secret_defaults():
    """
    Check the full client.yaml rendered for a default client.
    """
    secret = render("client/secret.yaml")
    assert secret["metadata"]["name"] == "myclient-zenith-client"
    assert secret["metadata"]["namespace"] == "ns"
    assert secret["metadata"]["labels"]["zenith.stackhpc.com/client"] == "myclient"
    assert client_config() == {
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


def test_secret_flags():
    """
    Check that debug, internal, skip-auth and scheme are rendered.
    """
    config = client_config(
        make_client(
            debug=True,
            internal=True,
            auth={"skip": True},
            upstream={"serviceName": "svc", "scheme": "https"},
        )
    )
    assert config["debug"] is True
    assert config["internal"] is True
    assert config["skip_auth"] is True
    assert config["backend_protocol"] == "https"


def test_secret_external_auth_params_are_merged_with_defaults(monkeypatch):
    """
    Check that client external auth params are merged over the operator defaults.
    """
    from zenith.operator.config import settings

    monkeypatch.setattr(
        settings, "default_external_auth_params", {"a": "default", "b": "default"}
    )
    config = client_config(
        make_client(auth={"external": {"params": {"b": "client", "c": "client"}}})
    )
    assert config["auth_external_params"] == {
        "a": "default",
        "b": "client",
        "c": "client",
    }


def test_secret_oidc_issuer():
    """
    Check that the OIDC issuer is rendered into the client config.
    """
    config = client_config(
        make_client(
            auth={
                "oidc": {
                    "issuer": "https://issuer.example.com",
                    "credentialsSecretName": "oidc",
                }
            }
        )
    )
    assert config["auth_oidc_issuer"].startswith("https://issuer.example.com")


def test_secret_forwards_to_mitm_proxy_when_enabled():
    """
    Check that traffic is forwarded to the local MITM proxy when enabled.
    """
    config = client_config(make_client(mitmProxy={"enabled": True, "port": 9090}))
    assert config["forward_to_host"] == "127.0.0.1"
    assert config["forward_to_port"] == 9090
    assert config["backend_protocol"] == "http"


def test_deployment_defaults():
    """
    Check a default deployment: one container, checksum annotation, no optional fields.
    """
    deployment = render("client/deployment.yaml", config_checksum="sum")
    assert deployment["metadata"]["name"] == "myclient-zenith-client"
    assert deployment["spec"]["replicas"] == 1
    template = deployment["spec"]["template"]
    assert template["metadata"]["annotations"] == {
        "zenith.stackhpc.com/config-checksum": "sum"
    }
    pod = template["spec"]
    assert list(containers(deployment)) == ["zenith-client"]
    assert "serviceAccountName" not in pod
    assert "imagePullSecrets" not in pod
    assert "nodeSelector" not in pod
    assert "affinity" not in pod
    assert "tolerations" not in pod
    assert {v["name"] for v in pod["volumes"]} == {"etc-zenith", "tmp"}
    assert env(containers(deployment)["zenith-client"]) == {}


def test_deployment_pod_scheduling_passthrough():
    """
    Check replicas, pull secrets, node selector, tolerations and affinity pass through.
    """
    client = make_client(
        replicaCount=3,
        imagePullSecrets=[{"name": "pull"}],
        nodeSelector={"disk": "ssd"},
        tolerations=[{"key": "k", "operator": "Exists"}],
        affinity={"nodeAffinity": {}},
    )
    deployment = render("client/deployment.yaml", client, config_checksum="sum")
    pod = deployment["spec"]["template"]["spec"]
    assert deployment["spec"]["replicas"] == 3
    assert pod["imagePullSecrets"] == [{"name": "pull"}]
    assert pod["nodeSelector"] == {"disk": "ssd"}
    assert pod["tolerations"] == [{"key": "k", "operator": "Exists"}]
    assert pod["affinity"] == {"nodeAffinity": {}}


def test_deployment_oidc_env():
    """
    Check that OIDC credentials are injected from the referenced secret.
    """
    client = make_client(
        auth={
            "oidc": {
                "issuer": "https://issuer.example.com",
                "credentialsSecretName": "oidc",
            }
        }
    )
    deployment = render("client/deployment.yaml", client, config_checksum="sum")
    oidc_env = env(containers(deployment)["zenith-client"])
    assert oidc_env["ZENITH_CLIENT__AUTH_OIDC_CLIENT_ID"]["valueFrom"] == {
        "secretKeyRef": {"name": "oidc", "key": "client-id"}
    }
    assert oidc_env["ZENITH_CLIENT__AUTH_OIDC_CLIENT_SECRET"]["valueFrom"] == {
        "secretKeyRef": {"name": "oidc", "key": "client-secret"}
    }


def mitm_deployment(auth_inject=None, **spec):
    """
    Render a deployment with the MITM proxy enabled and the given auth injection.
    """
    mitm = {"enabled": True, "port": 9090}
    if auth_inject:
        mitm["authInject"] = auth_inject
    client = make_client(
        mitmProxy=mitm,
        upstream={"serviceName": "svc", "scheme": "https"},
        **spec,
    )
    return render(
        "client/deployment.yaml",
        client,
        upstream_port=443,
        config_checksum="sum",
    )


def test_deployment_mitm_proxy_sidecar():
    """
    Check the MITM proxy sidecar, its env and its volumes.
    """
    deployment = mitm_deployment()
    assert list(containers(deployment)) == ["zenith-client", "mitm-proxy"]
    proxy_env = {
        k: v.get("value") for k, v in env(containers(deployment)["mitm-proxy"]).items()
    }
    assert proxy_env == {
        "ZENITH_PROXY_LISTEN_PORT": "9090",
        "ZENITH_PROXY_UPSTREAM_SCHEME": "https",
        "ZENITH_PROXY_UPSTREAM_HOST": "svc.ns.svc.cluster.local",
        "ZENITH_PROXY_UPSTREAM_PORT": "443",
    }
    assert "serviceAccountName" not in deployment["spec"]["template"]["spec"]
    volumes = {v["name"] for v in deployment["spec"]["template"]["spec"]["volumes"]}
    assert {"var-cache-nginx", "var-run-nginx"} <= volumes


def test_deployment_mitm_proxy_basic_auth():
    """
    Check Basic auth injection env vars on the MITM proxy.
    """
    proxy_env = env(containers(mitm_deployment(BASIC))["mitm-proxy"])
    assert proxy_env["ZENITH_PROXY_AUTH_INJECT"]["value"] == "basic"
    assert proxy_env["ZENITH_PROXY_AUTH_BASIC_USERNAME"]["valueFrom"] == {
        "secretKeyRef": {"name": "basic-creds", "key": "username"}
    }
    assert proxy_env["ZENITH_PROXY_AUTH_BASIC_PASSWORD"]["valueFrom"] == {
        "secretKeyRef": {"name": "basic-creds", "key": "password"}
    }


def test_deployment_mitm_proxy_bearer_auth():
    """
    Check Bearer auth injection env vars on the MITM proxy.
    """
    proxy_env = env(containers(mitm_deployment(BEARER))["mitm-proxy"])
    assert proxy_env["ZENITH_PROXY_AUTH_INJECT"]["value"] == "bearer"
    assert proxy_env["ZENITH_PROXY_AUTH_BEARER_HEADER"]["value"] == "Authorization"
    assert proxy_env["ZENITH_PROXY_AUTH_BEARER_PREFIX"]["value"] == "Bearer"
    assert proxy_env["ZENITH_PROXY_AUTH_BEARER_TOKEN"]["valueFrom"] == {
        "secretKeyRef": {"name": "bearer-creds", "key": "token"}
    }


def test_deployment_mitm_proxy_service_account_auth():
    """
    Check ServiceAccount auth injection and the pod's serviceAccountName.
    """
    deployment = mitm_deployment(SERVICE_ACCOUNT)
    proxy_env = env(containers(deployment)["mitm-proxy"])
    assert proxy_env["ZENITH_PROXY_AUTH_INJECT"]["value"] == "bearer"
    assert proxy_env["ZENITH_PROXY_AUTH_BEARER_TOKEN_FILE"]["value"].endswith("/token")
    pod = deployment["spec"]["template"]["spec"]
    assert pod["serviceAccountName"] == "myclient-zenith-client"


def test_service_account_and_cluster_role_binding():
    """
    Check the rendered ServiceAccount and ClusterRoleBinding.
    """
    client = make_client(mitmProxy={"enabled": True, "authInject": SERVICE_ACCOUNT})
    sa = render("client/serviceaccount.yaml", client)
    crb = render("client/clusterrolebinding.yaml", client)
    assert sa["metadata"]["name"] == "myclient-zenith-client"
    assert crb["metadata"]["name"] == "zenith-client:ns:myclient"
    assert crb["roleRef"]["name"] == "view"
    assert crb["subjects"] == [
        {"kind": "ServiceAccount", "namespace": "ns", "name": "myclient-zenith-client"}
    ]


@pytest.mark.xfail(
    reason="template uses read_timeout but the model field is named readTimeout",
    strict=True,
)
def test_read_timeout_is_rendered():
    """
    Document the known bug that the upstream read timeout is never rendered.
    """
    client = make_client(upstream={"serviceName": "svc", "readTimeout": 30})
    assert client_config(client)["read_timeout"] == 30
