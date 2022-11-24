import asyncio
import base64
import importlib.metadata
import logging
import os

from easykube import Configuration, ApiError, PRESENT

from pyhelm3 import Client as HelmClient

from .model import EventKind
from .ingress_modifier import INGRESS_MODIFIERS_ENTRY_POINT_GROUP


# Initialise the easykube config from the environment
ekconfig = Configuration.from_environment()


class ServiceReconciler:
    """
    Reconciles headless services in Kubernetes with information from another system.
    """
    def __init__(self, config):
        self.config = config
        self._helm_client = HelmClient(
            default_timeout = config.helm_client.default_timeout,
            executable = config.helm_client.executable,
            history_max_revisions = config.helm_client.history_max_revisions,
            insecure_skip_tls_verify = config.helm_client.insecure_skip_tls_verify,
            unpack_directory = config.helm_client.unpack_directory
        )
        self._logger = logging.getLogger(__name__)

    def _log(self, level, *args, **kwargs):
        getattr(self._logger, level)(*args, **kwargs)

    def _labels(self, name):
        """
        Returns the labels that identify a resource as belonging to a service.
        """
        return {
            self.config.created_by_label: "zenith-sync",
            self.config.service_name_label: name,
        }

    def _adopt(self, service, resource):
        """
        Adopts the given resource for the service.
        """
        metadata = resource.setdefault("metadata", {})
        labels = metadata.setdefault("labels", {})
        labels.update(self._labels(service.name))
        return resource

    async def _apply_tls(self, client, service, service_domain, ingress, ingress_modifier):
        """
        Applies the TLS configuration to an ingress resource.
        """
        # Add a TLS section if required
        tls_secret_name = None
        if "tls-cert" in service.config:
            # If the service pushed a TLS certificate, use it even if auto-TLS is disabled
            tls_secret_name = f"tls-{service.name}"
            # Make a secret with the certificate in to pass to the ingress
            secrets = await client.api("v1").resource("secrets")
            await secrets.create_or_replace(
                tls_secret_name,
                self._adopt(
                    service,
                    {
                        "metadata": {
                            "name": tls_secret_name,
                        },
                        "type": "kubernetes.io/tls",
                        "data": {
                            "tls.crt": service.config["tls-cert"],
                            "tls.key": service.config["tls-key"],
                        },
                    }
                )
            )
        elif self.config.ingress.tls.enabled:
            # If TLS is enabled, set a secret name even if the secret doesn't exist
            # cert-manager can be enabled using annotations
            tls_secret_name = self.config.ingress.tls.secret_name or f"tls-{service.name}"
            # Apply any TLS-specific annotations
            ingress["metadata"]["annotations"].update(self.config.ingress.tls.annotations)
        # Configure the TLS section
        if tls_secret_name:
            ingress["spec"]["tls"] = [
                {
                    "hosts": [service_domain],
                    "secretName": tls_secret_name,
                },
            ]
        # Configure client certificate handling if required
        if "tls-client-ca" in service.config:
            # First, make a secret containing the CA certificate
            client_ca_secret = f"tls-client-ca-{service.name}"
            secrets = await client.api("v1").resource("secrets")
            await secrets.create_or_replace(
                client_ca_secret,
                self._adopt(
                    service,
                    {
                        "metadata": {
                            "name": client_ca_secret,
                        },
                        "data": {
                            "ca.crt": service.config["tls-client-ca"]
                        }
                    }
                )
            )
            # Apply controller-specific modifications for client certificate handling
            ingress_modifier.configure_tls_client_certificates(
                ingress,
                self.config.target_namespace,
                client_ca_secret
            )

    async def _reconcile_oidc_proxy(self, release_name, client, service, service_domain):
        """
        Reconciles the oauth2-proxy release to do OIDC authentication for the service.
        """
        # Read the existing cookie secret so that we can reuse it
        # If it doesn't exist yet, generate one
        try:
            secrets = await client.api("v1").resource("secrets")
            secret = await secrets.fetch(release_name)
            cookie_secret = base64.b64decode(secret["data"]["cookie-secret"]).decode()
        except (ApiError, KeyError):
            # https://oauth2-proxy.github.io/oauth2-proxy/docs/configuration/overview#generating-a-cookie-secret
            cookie_secret = base64.urlsafe_b64encode(os.urandom(32)).decode()
        _ = await self._helm_client.ensure_release(
            release_name,
            await self._helm_client.get_chart(
                self.config.ingress.oidc.oauth2_proxy_chart_name,
                repo = self.config.ingress.oidc.oauth2_proxy_chart_repo,
                version = self.config.ingress.oidc.oauth2_proxy_chart_version
            ),
            # Start with the default values
            self.config.ingress.oidc.oauth2_proxy_default_values,
            # Override with service-specific values
            {
                "fullnameOverride": release_name,
                "config": {
                    "clientID": service.config["auth-oidc-client-id"],
                    "clientSecret": service.config["auth-oidc-client-secret"],
                    "cookieSecret": cookie_secret,
                },
                "extraArgs": {
                    "proxy-prefix": "/_oidc",
                    "cookie-expire": service.config.get("auth-oidc-cookie-expire", "24h"),
                    "whitelist-domain": service_domain,
                    "provider": "oidc",
                    "oidc-issuer-url": service.config["auth-oidc-issuer"],
                    "email-domain": "*",
                    "insecure-oidc-allow-unverified-email": (
                        "true"
                        if service.config.get("auth-oidc-allow-unverified-email", True)
                        else "false"
                    ),
                    "pass-access-token": "",
                    "set-xauthrequest": "",
                },
                # We will always manage our own ingress for the _oidc path
                "ingress": {
                    "enabled": False,
                },
            },
            cleanup_on_fail = True,
            # The namespace should exist, so we don't need to create it
            create_namespace = False,
            namespace = self.config.target_namespace
            # We don't need to wait, we just need to know that Helm created the resources
        )

    async def _reconcile_oidc_ingress(
        self,
        release_name,
        client,
        service,
        service_domain,
        ingress_modifier
    ):
        """
        Reconciles the ingress for the OIDC authentication for the service.
        """
        # Work out if there is a TLS secret we should use for the _oidc ingress
        tls_secret_name = None
        if "tls-cert" in service.config:
            tls_secret_name = f"tls-{service.name}"
        elif self.config.ingress.tls.enabled:
            tls_secret_name = self.config.ingress.tls.secret_name or f"tls-{service.name}"
        # Create an ingress without authentication for the _oidc path
        oidc_ingress = {
            "metadata": {
                "name": release_name,
                "labels": {},
                "annotations": {},
            },
            "spec": {
                "ingressClassName": self.config.ingress.class_name,
                "rules": [
                    {
                        "host": service_domain,
                        "http": {
                            "paths": [
                                {
                                    "path": "/_oidc",
                                    "pathType": "Prefix",
                                    "backend": {
                                        "service": {
                                            "name": release_name,
                                            "port": {
                                                "name": "http",
                                            },
                                        },
                                    },
                                },
                            ],
                        },
                    },
                ],
                "tls": (
                    [{ "hosts": [service_domain], "secretName": tls_secret_name }]
                    if tls_secret_name
                    else []
                ),
            },
        }
        ingress_modifier.configure_defaults(oidc_ingress)
        oidc_ingress["metadata"]["annotations"].update(self.config.ingress.annotations)
        ingresses = await client.api("networking.k8s.io/v1").resource("ingresses")
        await ingresses.create_or_replace(release_name, self._adopt(service, oidc_ingress))

    async def _apply_auth(self, client, service, service_domain, ingress, ingress_modifier):
        """
        Apply any authentication configuration defined in the configuration and/or
        service to the ingress.
        """
        auth_enabled = not service.config.get("skip-auth", False)
        auth_type = service.config.get("auth-type", "external")
        # If OIDC is enabled, we create an oauth2-proxy instance to delegate the auth to
        # If it is not enabled, we need to make sure that the instance does not exist
        oidc_release_name = f"oidc-{service.name}"
        if auth_enabled and auth_type == "oidc":
            await self._reconcile_oidc_proxy(
                oidc_release_name,
                client,
                service,
                service_domain
            )
            await self._reconcile_oidc_ingress(
                oidc_release_name,
                client,
                service,
                service_domain,
                ingress_modifier
            )
            # Configure authentication on the main ingress
            ingress_modifier.configure_authentication(
                ingress,
                "http://{name}.{namespace}.{domain}/_oidc/auth".format(
                    name = oidc_release_name,
                    namespace = self.config.target_namespace,
                    domain = self.config.cluster_services_domain
                ),
                "https://$host/_oidc/start",
                "rd",
                # Copy the oauth2-proxy auth request headers to the upstream request, but
                # rename them to the conventional names
                response_headers = [
                    ("X-Auth-Request-Preferred-Username", "X-Remote-User"),
                    ("X-Auth-Request-Groups", "X-Remote-Group"),
                    ("X-Auth-Request-Access-Token", "X-Access-Token"),
                ],
                # oauth2-proxy uses cookie splitting for large OIDC tokens
                # Make sure that we copy a reasonable number of split cookies to the main response
                response_cookies = [f"_oauth2_proxy_{i}" for i in range(1, 4)]
            )
        else:
            # Remove the ingress for the _oidc path
            ingresses = await client.api("networking.k8s.io/v1").resource("ingresses")
            await ingresses.delete(oidc_release_name)
            # Remove the Helm release for the oauth2-proxy
            _ = await self._helm_client.uninstall_release(
                oidc_release_name,
                namespace = self.config.target_namespace
            )
        # If external auth is enabled, we need to configure the ingress
        if auth_type == "external" and self.config.ingress.external_auth.url:
            # Determine what headers to set/override on the auth request
            #   Start with the fixed defaults
            request_headers = dict(self.config.ingress.external_auth.request_headers)
            #   Then set additional headers from the external auth params
            request_headers.update({
                f"{self.config.ingress.external_auth.param_header_prefix}{name}": value
                for name, value in service.config.get("auth-external-params", {})
            })
            ingress_modifier.configure_authentication(
                ingress,
                self.config.ingress.external_auth.url,
                self.config.ingress.external_auth.signin_url,
                self.config.ingress.external_auth.next_url_param,
                request_headers,
                self.config.ingress.external_auth.response_headers
            )

    async def _reconcile_service(self, client, service, ingress_modifier):
        """
        Reconciles a service with Kubernetes.
        """
        endpoints = ", ".join(f"{ep.address}:{ep.port}" for ep in service.endpoints)
        self._log("info", f"Reconciling {service.name} [{endpoints}]")
        # First create or update the corresponding service
        services = await client.api("v1").resource("services")
        await services.create_or_replace(
            service.name,
            self._adopt(
                service,
                {
                    "metadata": {
                        "name": service.name,
                    },
                    "spec": {
                        "ports": [
                            {
                                "protocol": "TCP",
                                "port": 80,
                                "targetPort": "dynamic",
                            },
                        ],
                    },
                }
            )
        )
        # Then create or update the endpoints object
        endpoints = await client.api("v1").resource("endpoints")
        await endpoints.create_or_replace(
            service.name,
            self._adopt(
                service,
                {
                    "metadata": {
                        "name": service.name,
                    },
                    "subsets": [
                        {
                            "addresses": [
                                {
                                    "ip": endpoint.address,
                                },
                            ],
                            "ports": [
                                {
                                    "port": endpoint.port,
                                },
                            ],
                        }
                        for endpoint in service.endpoints
                    ],
                }
            )
        )
        # Finally, create or update the ingress object
        service_domain = f"{service.name}.{self.config.ingress.base_domain}"
        ingress = {
            "metadata": {
                "name": service.name,
                "labels": {},
                "annotations": {},
            },
            "spec": {
                "ingressClassName": self.config.ingress.class_name,
                "rules": [
                    {
                        "host": service_domain,
                        "http": {
                            "paths": [
                                {
                                    "path": "/",
                                    "pathType": "Prefix",
                                    "backend": {
                                        "service": {
                                            "name": service.name,
                                            "port": {
                                                "name": "dynamic",
                                            },
                                        },
                                    },
                                },
                            ],
                        },
                    },
                ],
            },
        }
        # Apply controller-specific defaults to the ingress
        ingress_modifier.configure_defaults(ingress)
        # Apply custom annotations after the controller defaults
        ingress["metadata"]["annotations"].update(self.config.ingress.annotations)
        # Apply controller-specific modifications for the backend protocol
        protocol = service.config.get("backend-protocol", "http")
        ingress_modifier.configure_backend_protocol(ingress, protocol)
        # Apply controller-specific modifications for the read timeout, if given
        read_timeout = service.config.get("read-timeout")
        if read_timeout:
            # Check that the read timeout is an int - if it isn't don't use it
            try:
                read_timeout = int(read_timeout)
            except ValueError:
                self._log("warn", "Given read timeout is not a valid integer")
            else:
                ingress_modifier.configure_read_timeout(ingress, read_timeout)
        # Apply any TLS configuration
        await self._apply_tls(client, service, service_domain, ingress, ingress_modifier)
        # Apply any auth configuration
        await self._apply_auth(client, service, service_domain, ingress, ingress_modifier)
        # Create or update the ingress
        ingresses = await client.api("networking.k8s.io/v1").resource("ingresses")
        await ingresses.create_or_replace(service.name, self._adopt(service, ingress))

    async def _remove_service(self, client, name):
        """
        Removes a service from Kubernetes.
        """
        self._log("info", f"Removing {name}")
        # We have to delete the corresponding endpoints, services, ingresses and secrets
        ingresses = await client.api("networking.k8s.io/v1").resource("ingresses")
        await ingresses.delete_all(labels = self._labels(name))
        endpoints = await client.api("v1").resource("endpoints")
        await endpoints.delete_all(labels = self._labels(name))
        services = await client.api("v1").resource("services")
        await services.delete_all(labels = self._labels(name))
        # This will leave behind secrets created by cert-manager, which is fine because
        # it means that if a reconnection occurs for the same domain it will be a
        # renewal which doesn't count towards the rate limit
        secrets = await client.api("v1").resource("secrets")
        await secrets.delete_all(labels = self._labels(name))
        # Remove any OIDC components that were created
        await self._helm_client.uninstall_release(
            f"oidc-{name}",
            namespace = self.config.target_namespace
        )

    async def run(self, source):
        """
        Run the reconciler against services from the given service source.
        """
        self._log("info", f"Reconciling services [namespace: {self.config.target_namespace}]")
        async with ekconfig.async_client(default_namespace = self.config.target_namespace) as client:
            # Before we process the service, retrieve information about the ingress class
            ingress_classes = await client.api("networking.k8s.io/v1").resource("ingressclasses")
            ingress_class = await ingress_classes.fetch(self.config.ingress.class_name)
            # Load the ingress modifier that handles the controller
            entry_points = importlib.metadata.entry_points()[INGRESS_MODIFIERS_ENTRY_POINT_GROUP]
            ingress_modifier = next(
                ep.load()()
                for ep in entry_points
                if ep.name == ingress_class["spec"]["controller"]
            )
            initial_services, events, _ = await source.subscribe()
            # Before we start listening to events, we reconcile the existing services
            # We also remove any services that exist that are not part of the initial set
            # The returned value from the list operation is an async generator, which we must resolve
            services = await client.api("v1").resource("services")
            existing_services = {
                service["metadata"]["name"]
                async for service in services.list(labels = self._labels(PRESENT))
            }
            tasks = [
                self._reconcile_service(client, service, ingress_modifier)
                for service in initial_services
            ] + [
                self._remove_service(client, name)
                for name in existing_services.difference(s.name for s in initial_services)
            ]
            await asyncio.gather(*tasks)
            # Once the initial state has been synchronised, start processing events
            async for event in events:
                if event.kind == EventKind.DELETED:
                    await self._remove_service(client, event.service.name)
                else:
                    await self._reconcile_service(client, event.service, ingress_modifier)


class TLSSecretMirror:
    """
    Mirrors the wildcard secret from the sync namespace to the target namespace for services.
    """
    def __init__(self, config):
        self.config = config
        self._logger = logging.getLogger(__name__)

    async def _update_mirror(self, client, source_object):
        """
        Updates the mirror secret in the target namespace.
        """
        self._logger.info(
            "Updating mirrored TLS secret '%s' in namespace '%s'",
            self.config.ingress.tls.secret_name,
            self.config.target_namespace
        )
        secrets = await client.api("v1").resource("secrets")
        await secrets.create_or_replace(
            self.config.ingress.tls.secret_name,
            {
                "metadata": {
                    "name": self.config.ingress.tls.secret_name,
                    "labels": {
                        self.config.created_by_label: "zenith-sync",
                    },
                    "annotations": {
                        self.config.tls_mirror_annotation: "{}/{}".format(
                            source_object["metadata"]["namespace"],
                            source_object["metadata"]["name"]
                        ),
                    },
                },
                "type": source_object["type"],
                "data": source_object["data"],
            },
            namespace = self.config.target_namespace
        )

    async def _delete_mirror(self, client):
        """
        Deletes the mirror secret in the target namespace.
        """
        self._logger.info(
            "Deleting mirrored TLS secret '%s' in namespace '%s'",
            self.config.ingress.tls.secret_name,
            self.config.target_namespace
        )
        secrets = await client.api("v1").resource("secrets")
        await secrets.delete(
            self.config.ingress.tls.secret_name,
            namespace = self.config.target_namespace
        )

    async def run(self):
        """
        Run the TLS secret mirror.
        """
        if self.config.ingress.tls.enabled and self.config.ingress.tls.secret_name:
            async with ekconfig.async_client() as client:
                self._logger.info(
                    "Mirroring TLS secret [secret: %s, from: %s, to: %s]",
                    self.config.ingress.tls.secret_name,
                    self.config.self_namespace,
                    self.config.target_namespace
                )
                # Watch the named secret in the release namespace for changes
                secrets = await client.api("v1").resource("secrets")
                initial_state, events = await secrets.watch_one(
                    self.config.ingress.tls.secret_name,
                    namespace = self.config.self_namespace
                )
                # Mirror the changes to the target namespace
                if initial_state:
                    await self._update_mirror(client, initial_state)
                else:
                    await self._delete_mirror(client)
                async for event in events:
                    if event["type"] != "DELETED":
                        await self._update_mirror(client, event["object"])
                    else:
                        await self._delete_mirror(client)
        else:
            self._logger.info("Mirroring of wildcard TLS secret is not required")
            while True:
                await asyncio.sleep(86400)
