import asyncio
import base64
import copy
import dataclasses
import json
import logging
import os
import typing

from easykube import Configuration, ApiError

from pyhelm3 import Client as HelmClient

from .. import config, metrics, model, store, util

from . import base


class ServiceHelmStatus(metrics.Metric):
    prefix = "zenith_service"
    suffix = "helm_status"
    description = "The Helm status for Zenith services"

    def labels(self, obj):
        return {
            "service_namespace": obj["namespace"],
            "service_name": obj["name"],
            "status": obj["status"],
        }


class Processor(base.Processor):
    """
    Reconciles services by using a Helm chart to create resources in Kubernetes.
    """

    def __init__(self, config: config.KubernetesConfig):
        self.config = config
        # Initialise an easykube client from the environment
        self.ekclient = Configuration.from_environment().async_client(
            default_field_manager=self.config.easykube_field_manager,
            default_namespace=self.config.target_namespace,
        )
        self.helm_client = HelmClient(
            default_timeout=config.helm_client.default_timeout,
            executable=config.helm_client.executable,
            history_max_revisions=config.helm_client.history_max_revisions,
            insecure_skip_tls_verify=config.helm_client.insecure_skip_tls_verify,
            unpack_directory=config.helm_client.unpack_directory,
        )
        super().__init__(
            logging.getLogger(__name__),
            config.reconciliation_max_concurrency,
            config.reconciliation_max_backoff,
        )

    async def startup(self):
        """
        Perform any startup tasks that are required.
        """
        await self.ekclient.__aenter__()

    async def shutdown(self):
        """
        Perform any shutdown tasks that are required.
        """
        await self.ekclient.__aexit__(None, None, None)

    async def _reconcile_oidc_credentials(
        self, service: model.Service
    ) -> typing.Tuple[str, str, str, typing.List[str]]:
        """
        Returns the OIDC issuer, client ID, secret and allowed groups for the given service.
        """
        oidc_issuer = service.config.get("auth-oidc-issuer")
        # If the issuer is present in the config, then a client ID and secret should also be there
        if oidc_issuer:
            return (
                oidc_issuer,
                service.config["auth-oidc-client-id"],
                service.config["auth-oidc-client-secret"],
                service.config.get("auth-oidc-allowed-groups", []),
            )
        # Otherwise, we need to wait for the discovery secret to become available
        secrets = await self.ekclient.api("v1").resource("secrets")
        try:
            secret = await secrets.fetch(
                self.config.ingress.oidc.discovery_secret_name_template.format(
                    service_name=service.name
                )
            )
        except ApiError as exc:
            if exc.status_code == 404:
                raise base.RetryRequired("oidc discovery secret not available")
            else:
                raise
        secret_data = {
            key: base64.b64decode(value).decode()
            for key, value in secret.get("data", {}).items()
        }
        allowed_groups_json = secret_data.get("allowed-groups")
        return (
            secret_data["issuer-url"],
            secret_data["client-id"],
            secret_data["client-secret"],
            json.loads(allowed_groups_json) if allowed_groups_json else [],
        )

    async def _reconcile_oidc_cookie_secret(self, service: model.Service) -> str:
        """
        Returns the cookie secret for the OAuth2 proxy for the service.
        """
        secrets = await self.ekclient.api("v1").resource("secrets")
        secret_name = (
            self.config.ingress.oidc.oauth2_proxy_cookie_secret_template.format(
                service_name=service.name
            )
        )
        try:
            secret = await secrets.fetch(secret_name)
        except ApiError as exc:
            if exc.status_code == 404:
                cookie_secret = base64.urlsafe_b64encode(os.urandom(32)).decode()
                secret = await self.ekclient.apply_object(
                    {
                        "apiVersion": "v1",
                        "kind": "Secret",
                        "metadata": {
                            "name": secret_name,
                            "labels": {
                                self.config.created_by_label: "zenith-sync",
                                self.config.service_name_label: service.name,
                            },
                        },
                        "stringData": {
                            "cookie-secret": cookie_secret,
                        },
                    },
                    force=True,
                )
            else:
                raise
        return base64.b64decode(secret.data["cookie-secret"]).decode()

    def _get_trust_values(self) -> typing.Dict[str, typing.Any]:
        """
        Returns the values for configuring a custom trust bundle for the OIDC callout.
        """
        if self.config.trust_bundle_configmap_name:
            # Make sure that the OIDC pods trust the bundle
            return {
                "oidc": {
                    "extraVolumes": [
                        {
                            "name": "trust-bundle",
                            "configMap": {
                                "name": self.config.trust_bundle_configmap_name,
                            },
                        },
                    ],
                    "extraVolumeMounts": [
                        {
                            "name": "trust-bundle",
                            "mountPath": "/etc/ssl/certs",
                            "readOnly": True,
                        },
                    ],
                },
            }
        else:
            return {}

    def _get_service_values(
        self, service: model.Service
    ) -> typing.Dict[str, typing.Any]:
        """
        Returns the values for the core service configuration.
        """
        # Build the core values for the service
        values = {
            "global": {
                "baseDomain": self.config.ingress.base_domain,
                "subdomain": service.name,
                "subdomainAsPathPrefix": self.config.ingress.subdomain_as_path_prefix,
            },
            "endpoints": [dataclasses.asdict(ep) for ep in service.endpoints],
            "protocol": service.config.get("backend-protocol", "http"),
            "ingress": {
                "annotations": self.config.ingress.annotations,
            },
        }
        read_timeout = service.config.get("read-timeout")
        if read_timeout:
            # Check that the read timeout is an int - if it isn't don't use it
            try:
                read_timeout = int(read_timeout)
            except ValueError:
                self.logger.warn("Given read timeout is not a valid integer")
            else:
                values["readTimeout"] = read_timeout
        return values

    def _get_ingress_enabled(
        self, service: model.Service
    ) -> typing.Dict[str, typing.Any]:
        """
        Returns the values for enabling or disabling ingress as required.
        """
        return {
            "ingress": {
                # Ingress is enabled unless specified
                "enabled": not service.config.get("internal", False),
            },
        }

    def _get_tls_values(self, service: model.Service) -> typing.Dict[str, typing.Any]:
        """
        Returns the values for configuring the TLS for a service.
        """
        tls_enabled = self.config.ingress.tls.enabled or "tls-cert" in service.config
        values = {"global": {"secure": tls_enabled}}
        if not tls_enabled:
            return values
        tls_values = values.setdefault("ingress", {}).setdefault("tls", {})
        if "tls-cert" in service.config:
            tls_values["existingCertificate"] = {
                "cert": service.config["tls-cert"],
                "key": service.config["tls-key"],
            }
        elif self.config.ingress.tls.terminated_at_proxy:
            tls_values["terminatedAtProxy"] = True
        elif self.config.ingress.tls.secret_name:
            tls_values["secretName"] = self.config.ingress.tls.secret_name
        else:
            tls_values["annotations"] = self.config.ingress.tls.annotations
        if "tls-client-ca" in service.config:
            tls_values["clientCA"] = service.config["tls-client-ca"]
        return values

    async def _get_auth_values(
        self, service: model.Service
    ) -> typing.Dict[str, typing.Any]:
        """
        Returns the values for configuring the auth for a service.

        This may involve querying and/or creating secrets.
        """
        # Decide what authentication to apply
        # This is done with the following precedence:
        #   1. If the client opted out of auth, no auth is applied
        #   2. If the client specified OIDC credentials, use them
        #   3. If OIDC discovery is enabled, use that
        #      This allows an external controller to place secrets into the Zenith namespace
        #      containing OIDC credentials for each service
        #   4. If external auth is configured, use that
        #   5. No auth is applied
        values = {}
        if service.config.get("skip-auth", False):
            values["oidc"] = {"enabled": False}
            values["externalAuth"] = {"enabled": False}
        elif (
            service.config.get("auth-oidc-issuer")
            or self.config.ingress.oidc.discovery_enabled
        ):
            (
                issuer_url,
                client_id,
                client_secret,
                allowed_groups,
            ) = await self._reconcile_oidc_credentials(service)
            cookie_secret = await self._reconcile_oidc_cookie_secret(service)
            values["oidc"] = {
                "enabled": True,
                "provider": {
                    "clientID": client_id,
                    "clientSecret": client_secret,
                    "allowedGroups": allowed_groups,
                    "loginURLParameters": self.config.ingress.oidc.forwarded_query_params,
                    "oidcConfig": {
                        "issuerURL": issuer_url,
                    },
                },
                "alphaConfig": {
                    "configData": {
                        "injectResponseHeaders": [
                            {"name": h, "values": [{"claim": c}]}
                            for h, c in self.config.ingress.oidc.inject_request_headers.items()
                        ],
                    },
                },
                "extraArgs": {
                    "cookie-secret": cookie_secret,
                },
            }
        elif self.config.ingress.external_auth.url:
            values["externalAuth"] = {
                "enabled": True,
                "url": self.config.ingress.external_auth.url,
                "signinUrl": self.config.ingress.external_auth.signin_url,
                "nextUrlParam": self.config.ingress.external_auth.next_url_param,
                "requestHeaders": self.config.ingress.external_auth.request_headers,
                "responseHeaders": self.config.ingress.external_auth.response_headers,
                "paramHeaderPrefix": self.config.ingress.external_auth.param_header_prefix,
                "params": service.config.get("auth-external-params", {}),
            }
        return values

    async def known_services(self) -> typing.Set[str]:
        releases = await self.helm_client.list_releases(
            all=True, max_releases=0, namespace=self.config.target_namespace
        )
        return {release.name for release in releases}

    async def service_updated(self, service: model.Service):
        endpoints = ", ".join(f"{ep.address}:{ep.port}" for ep in service.endpoints)
        self.logger.info(f"Reconciling {service.name} [{endpoints}]")
        # Install the Helm release
        _ = await self.helm_client.ensure_release(
            service.name,
            await self.helm_client.get_chart(
                self.config.service_chart_name,
                repo=self.config.service_chart_repo,
                version=self.config.service_chart_version,
            ),
            self.config.service_default_values,
            self._get_trust_values(),
            self._get_service_values(service),
            self._get_ingress_enabled(service),
            self._get_tls_values(service),
            await self._get_auth_values(service),
            cleanup_on_fail=True,
            # The namespace should exist, so we don't need to create it
            create_namespace=False,
            namespace=self.config.target_namespace,
            # Wait for the components to become ready
            wait=True,
        )

    async def service_removed(self, service: model.Service):
        self.logger.info(f"Removing {service.name}")
        # Remove the Helm release for the service
        await self.helm_client.uninstall_release(
            service.name, namespace=self.config.target_namespace, wait=True
        )
        # Delete the OIDC cookie secret if required
        secrets = await self.ekclient.api("v1").resource("secrets")
        secret_name = (
            self.config.ingress.oidc.oauth2_proxy_cookie_secret_template.format(
                service_name=service.name
            )
        )
        await secrets.delete(secret_name)

    async def metrics(self) -> typing.Iterable[metrics.Metric]:
        # Drop down to the Helm command to get statuses without extra Helm commands
        releases = await self.helm_client._command.list(
            all=True, max_releases=0, namespace=self.config.target_namespace
        )
        helm_status_metric = ServiceHelmStatus()
        for release in releases:
            helm_status_metric.add_obj(release)
        return [helm_status_metric]

    async def _watch_events(self, ekresource, name, namespace):
        """
        Yields watch events for the specified object, including a synthetic add/delete event
        for the initial state.
        """
        initial_state, events = await ekresource.watch_one(name, namespace=namespace)
        if initial_state:
            yield {"type": "ADDED", "object": initial_state}
        else:
            yield {
                "type": "DELETED",
                "object": {
                    "metadata": {
                        "name": name,
                        "namespace": namespace,
                    },
                },
            }
        async for event in events:
            yield event

    async def _mirror_obj(self, ekresource, name, source_namespace, target_namespace):
        """
        Mirrors the specified object from the source namespace to the target namespace.
        """
        self.logger.info(
            "Mirroring object [apiVersion: %s, kind: %s, name: %s, from: %s, to: %s]",
            ekresource.api_version,
            ekresource.kind,
            name,
            source_namespace,
            target_namespace,
        )
        async for event in self._watch_events(ekresource, name, source_namespace):
            # Prepare the mirror object from the source object
            mirror_obj = copy.deepcopy(event["object"])
            # Make sure that the API version and kind are present
            mirror_obj.setdefault("apiVersion", ekresource.api_version)
            mirror_obj.setdefault("kind", ekresource.kind)
            # Replace the metadata object with one containing only what we need
            mirror_obj["metadata"] = {
                "name": mirror_obj["metadata"]["name"],
                # Set the namespace to the target namespace
                "namespace": target_namespace,
                "labels": {self.config.created_by_label: "zenith-sync"},
                "annotations": {
                    self.config.mirror_annotation: f"{source_namespace}/{name}"
                },
            }

            if event["type"] == "DELETED":
                self.logger.info(
                    "Deleting mirrored object [apiVersion: %s, kind: %s, name: %s, ns: %s]",
                    ekresource.api_version,
                    ekresource.kind,
                    mirror_obj["metadata"]["name"],
                    mirror_obj["metadata"]["namespace"],
                )
                await ekresource.delete(
                    mirror_obj["metadata"]["name"],
                    namespace=mirror_obj["metadata"]["namespace"],
                )
            else:
                self.logger.info(
                    "Updating mirrored object [apiVersion: %s, kind: %s, name: %s, ns: %s]",
                    ekresource.api_version,
                    ekresource.kind,
                    mirror_obj["metadata"]["name"],
                    mirror_obj["metadata"]["namespace"],
                )
                await ekresource.server_side_apply(
                    mirror_obj["metadata"]["name"],
                    mirror_obj,
                    namespace=mirror_obj["metadata"]["namespace"],
                    force=True,
                )

    async def _run_trust_bundle_mirror(self):
        """
        Continuously mirrors the trust bundle into the target namespace.
        """
        # We need to mirror TLS secrets alongside handling events
        if self.config.trust_bundle_configmap_name:
            configmaps = await self.ekclient.api("v1").resource("configmaps")
            await self._mirror_obj(
                configmaps,
                self.config.trust_bundle_configmap_name,
                self.config.self_namespace,
                self.config.target_namespace,
            )
        else:
            self.logger.info("Mirroring of trust bundle configmap is not required")
            while True:
                await asyncio.Event().wait()

    async def _run_tls_mirror(self):
        """
        Continuously mirrors the TLS secret into the target namespace.
        """
        # We need to mirror TLS secrets alongside handling events
        if self.config.ingress.tls.enabled and self.config.ingress.tls.secret_name:
            secrets = await self.ekclient.api("v1").resource("secrets")
            await self._mirror_obj(
                secrets,
                self.config.ingress.tls.secret_name,
                self.config.self_namespace,
                self.config.target_namespace,
            )
        else:
            self.logger.info("Mirroring of wildcard TLS secret is not required")
            while True:
                await asyncio.Event().wait()

    async def run(self, store: store.Store):
        # We need to run the TLS mirror alongside the main loop
        done, not_done = await asyncio.wait(
            [
                asyncio.create_task(super().run(store)),
                asyncio.create_task(self._run_trust_bundle_mirror()),
                asyncio.create_task(self._run_tls_mirror()),
            ],
            return_when=asyncio.FIRST_COMPLETED,
        )
        # Any exceptions are not raised until the result is requested
        # We also cancel the other task
        for task in not_done:
            await util.task_cancel_and_wait(task)
        for task in done:
            task.result()

    @classmethod
    def from_config(cls, config_obj: config.SyncConfig) -> "Processor":
        return cls(config_obj.kubernetes)
