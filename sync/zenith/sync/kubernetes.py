import asyncio
import importlib.metadata
import logging
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs

from easykube import Configuration, resources as k8s

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
        if "tls-cert" in service.tls:
            # If the service pushed a TLS certificate, use it even if auto-TLS is disabled
            tls_secret_name = f"tls-{service.name}"
            # Make a secret with the certificate in to pass to the ingress
            await k8s.Secret(client).create_or_patch(
                tls_secret_name,
                self._adopt(
                    service,
                    {
                        "type": "kubernetes.io/tls",
                        "data": {
                            "tls.crt": service.tls["tls-cert"],
                            "tls.key": service.tls["tls-key"],
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
        if "tls-client-ca" in service.tls:
            # First, make a secret containing the CA certificate
            client_ca_secret = f"tls-client-ca-{service.name}"
            await k8s.Secret(client).create_or_patch(
                client_ca_secret,
                self._adopt(
                    service,
                    {
                        "data": {
                            "ca.crt": service.tls["tls-client-ca"]
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

    def _apply_auth(self, service, ingress, ingress_modifier):
        """
        Apply any authentication configuration defined in the configuration and/or
        service to the ingress.
        """
        # If there is no auth service in the configuration, do nothing
        if not self.config.ingress.auth.url:
            return
        # If the service declared that it wants to skip authentication, then do nothing
        # The metadata items are all strings, but this is set to either 0 or 1 by the SSHD component
        skip_auth = service.metadata.get(self.config.ingress.auth.skip_auth_metadata_key, "0")
        if skip_auth == "1":
            return
        # Apply the auth configuration, which may be ingress-controller specific
        auth_params = {
            name.removeprefix(self.config.ingress.auth.param_metadata_prefix): value
            for name, value in service.metadata.items()
            if name.startswith(self.config.ingress.auth.param_metadata_prefix)
        }
        # Determine the signin URL - we add the auth params as GET parameters
        signin_url_info = urlparse(self.config.ingress.auth.signin_url)
        signin_url_query_params = parse_qs(signin_url_info.query, keep_blank_values = True)
        for name, value in auth_params.items():
            signin_url_query_params.setdefault(name, []).append(value)
        signin_url = urlunparse(
            signin_url_info._replace(
                query = urlencode(signin_url_query_params, doseq = True)
            )
        )
        # Determine what headers to set/override on the auth request
        #   Start with the fixed defaults
        request_headers = dict(self.config.ingress.auth.request_headers)
        #   Set additional headers from the auth params in the service metadata
        request_headers.update({
            f"{self.config.ingress.auth.param_header_prefix}{name}": value
            for name, value in auth_params.items()
        })
        ingress_modifier.configure_authentication(
            ingress,
            self.config.ingress.auth.url,
            signin_url,
            self.config.ingress.auth.next_url_param,
            request_headers,
            self.config.ingress.auth.response_headers
        )


    async def _reconcile_service(self, client, service, ingress_modifier):
        """
        Reconciles a service with Kubernetes.
        """
        endpoints = ", ".join(f"{ep.address}:{ep.port}" for ep in service.endpoints)
        self._log("info", f"Reconciling {service.name} [{endpoints}]")
        # First create or update the corresponding service
        await k8s.Service(client).create_or_patch(
            service.name,
            self._adopt(
                service,
                {
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
        await k8s.Endpoints(client).create_or_patch(
            service.name,
            self._adopt(
                service,
                {
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
        protocol = service.metadata.get(self.config.ingress.backend_protocol_metadata_key, "http")
        ingress_modifier.configure_backend_protocol(ingress, protocol)
        # Apply controller-specific modifications for the read timeout, if given
        read_timeout = service.metadata.get(self.config.ingress.read_timeout_metadata_key)
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
        self._apply_auth(service, ingress, ingress_modifier)
        # Create or update the ingress
        await k8s.Ingress(client).create_or_patch(service.name, self._adopt(service, ingress))

    async def _remove_service(self, client, name):
        """
        Removes a service from Kubernetes.
        """
        self._log("info", f"Removing {name}")
        # We have to delete the corresponding endpoints, service and ingress objects
        await k8s.Ingress(client).delete(name)
        await k8s.Endpoints(client).delete(name)
        await k8s.Service(client).delete(name)
        # Also delete any secrets created for the service
        # This will leave behind secrets created by cert-manager, which is fine because
        # it means that if a reconnection occurs for the same domain it will be a
        # renewal which doesn't count towards the rate limit
        await k8s.Secret(client).delete_all(labels = self._labels(name))

    async def run(self, source):
        """
        Run the reconciler against services from the given service source.
        """
        self._log("info", f"Reconciling services [namespace: {self.config.target_namespace}]")
        async with ekconfig.async_client(default_namespace = self.config.target_namespace) as client:
            # Before we process the service, retrieve information about the ingress class
            ingress_class = await k8s.IngressClass(client).fetch(self.config.ingress.class_name)
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
            existing_services = set()
            async for service in k8s.Service(client).list():
                existing_services.add(service["metadata"]["name"])
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
        await k8s.Secret(client).create_or_patch(
            self.config.ingress.tls.secret_name,
            {
                "metadata": {
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
        await k8s.Secret(client).delete(
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
                initial_state, events = await k8s.Secret(client).watch_one(
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
