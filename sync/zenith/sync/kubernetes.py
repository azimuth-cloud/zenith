import asyncio
import base64
import hashlib
import importlib.metadata
import json
import logging
import random
import os

import yaml

from easykube import Configuration, ApiError, PRESENT

from pyhelm3 import Client as HelmClient

from .model import Event, EventKind, Service
from .ingress_modifier import INGRESS_MODIFIERS_ENTRY_POINT_GROUP


# Initialise the easykube config from the environment
ekconfig = Configuration.from_environment()


class EventQueue(asyncio.Queue):
    """
    Customised queue implementation that understands service events.

    A new event for a service replaces those that are retries, as they
    are no longer up-to-date.
    """
    def __init__(self, max_backoff, maxsize = 0):
        super().__init__(maxsize)
        self._max_backoff = max_backoff

    def _init(self, maxsize):
        self._queue = []
        # The requeue tasks are indexed by service
        # This allows us to cancel them when a new event comes in
        self._requeue_tasks = {}

    def _put(self, item):
        if isinstance(item, Event):
            incoming_event, incoming_retries = item, 0
        else:
            incoming_event, incoming_retries = item
        # Cancel any requeue tasks for the service before pushing the new event
        requeue_task = self._requeue_tasks.pop(incoming_event.service.name, None)
        if requeue_task and not requeue_task.done():
            requeue_task.cancel()
        # If there is an existing event for the the service in the queue, find it
        # We will only keep one from the existing event and the incoming one
        # The one that we keep will be the one with the fewest retries
        # Whichever event we keep will be moved to the back of the queue
        # This ensures that "stable" services are dealt with first
        try:
            existing_idx = next(
                idx
                for idx, (event, _) in enumerate(self._queue)
                if event.service.name == incoming_event.service.name
            )
        except StopIteration:
            # If there is no existing event, just append the incoming event
            self._queue.append((incoming_event, incoming_retries))
        else:
            # Otherwise, append the event with the least retries
            # If the retries are equal, we keep the incoming event
            existing_event, existing_retries = self._queue.pop(existing_idx)
            if incoming_retries <= existing_retries:
                self._queue.append((incoming_event, incoming_retries))
            else:
                self._queue.append((existing_event, existing_retries))

    def _get(self):
        return self._queue.pop(0)

    def requeue(self, event, retries):
        """
        Requeues the given event with the given number of retries.
        """
        service = event.service.name
        # Cancel any existing requeue task
        existing_task = self._requeue_tasks.pop(service, None)
        if existing_task and not existing_task.done():
            existing_task.cancel()
        # Launch a new background task to requeue the event after a backoff
        # We use an exponential backoff
        backoff = min(2**retries + random.uniform(0, 1), self._max_backoff)
        task = self._requeue_tasks[service] = asyncio.create_task(asyncio.sleep(backoff))
        # We use a done callback to put the event back onto the queue
        # It is important that this happens _outside_ the task as the put cancels the running task
        def done_callback(task):
            # If the task was cancelled, there is nothing to do
            try:
                _ = task.result()
            except asyncio.CancelledError:
                return
            # If the task completed successfully, requeue the event
            # If the queue is full, schedule another requeue attempt
            try:
                self.put_nowait((event, retries + 1))
            except asyncio.QueueFull:
                self.requeue(event, retries + 1)
        task.add_done_callback(done_callback)


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
            await client.apply_object(
                self._adopt(
                    service,
                    {
                        "apiVersion": "v1",
                        "kind": "Secret",
                        "metadata": {
                            "name": tls_secret_name,
                        },
                        "type": "kubernetes.io/tls",
                        "data": {
                            "tls.crt": service.config["tls-cert"],
                            "tls.key": service.config["tls-key"],
                        },
                    }
                ),
                force = True
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
            await client.apply_object(
                self._adopt(
                    service,
                    {
                        "apiVersion": "v1",
                        "kind": "Secret",
                        "metadata": {
                            "name": client_ca_secret,
                        },
                        "data": {
                            "ca.crt": service.config["tls-client-ca"]
                        }
                    }
                ),
                force = True
            )
            # Apply controller-specific modifications for client certificate handling
            ingress_modifier.configure_tls_client_certificates(
                ingress,
                self.config.target_namespace,
                client_ca_secret
            )

    async def _reconcile_oidc_credentials(self, client, service):
        """
        Returns the OIDC issuer, client ID and secret for the given service.
        """
        oidc_issuer = service.config.get("auth-oidc-issuer")
        # If the issuer is present in the config, then a client ID and secret should also be there
        if oidc_issuer:
            return (
                oidc_issuer,
                service.config["auth-oidc-client-id"],
                service.config["auth-oidc-client-secret"],
                service.config.get("auth-oidc-allowed-groups", []),
            )
        # Otherwise, we need to wait for the discovery secret to become available
        secrets = await client.api("v1").resource("secrets")
        secret = await secrets.fetch(
            self.config.ingress.oidc.discovery_secret_name_template.format(
                service_name = service.name
            )
        )
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

    async def _reconcile_oidc_cookie_secret(self, client, service):
        """
        Returns the cookie secret for the OAuth2 proxy for the service.
        """
        secrets = await client.api("v1").resource("secrets")
        secret_name = self.config.ingress.oidc.oauth2_proxy_cookie_secret_template.format(
            service_name = service.name
        )
        try:
            secret = await secrets.fetch(secret_name)
        except ApiError as exc:
            if exc.status_code == 404:
                cookie_secret = base64.urlsafe_b64encode(os.urandom(32)).decode()
                secret = await client.apply_object(
                    self._adopt(
                        service,
                        {
                            "apiVersion": "v1",
                            "kind": "Secret",
                            "metadata": {
                                "name": secret_name,
                            },
                            "stringData": {
                                "cookie-secret": cookie_secret,
                            },
                        }
                    ),
                    force = True
                )
            else:
                raise
        return base64.b64decode(secret.data["cookie-secret"]).decode()

    def _oauth2_proxy_alpha_config(self, issuer_url, client_id, client_secret, allowed_groups):
        """
        Returns the OAuth2 proxy alpha config for the service, and the checksum
        of the config (the chart does not currently include an annotation for it).
        """
        config = {
            "injectResponseHeaders": [
                {
                    "name": "X-Remote-User",
                    "values": [
                        { "claim": "preferred_username" }
                    ],
                },
                {
                    "name": "X-Remote-Group",
                    "values": [
                        { "claim": "groups" }
                    ],
                },
            ],
            "upstreamConfig": {
                "upstreams": [
                    {
                        "id": "static",
                        "path": "/",
                        "static": True,
                    },
                ],
            },
            "providers": [
                {
                    "id": "oidc",
                    "provider": "oidc",
                    "clientID": client_id,
                    "clientSecret": client_secret,
                    "allowedGroups": allowed_groups,
                    "loginURLParameters": self.config.ingress.oidc.forwarded_query_params,
                    "oidcConfig": {
                        "issuerURL": issuer_url,
                        "insecureAllowUnverifiedEmail": True,
                        # Use a claim that is always available, in case email is not
                        "emailClaim": "sub",
                        "groupsClaim": "groups",
                        "audienceClaims": ["aud"],
                    },
                },
            ],
        }
        # Generate the checksum from the YAML representation
        checksum = hashlib.sha256(yaml.safe_dump(config).encode()).hexdigest()
        return config, checksum

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
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
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
                                    "path": self.config.ingress.oidc.oauth2_proxy_path_prefix,
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
        await client.apply_object(self._adopt(service, oidc_ingress), force = True)

    async def _reconcile_oidc_proxy(
        self,
        client,
        service,
        service_domain,
        issuer_url,
        client_id,
        client_secret,
        allowed_groups,
        ingress_modifier
    ):
        """
        Reconciles the oauth2-proxy release to do OIDC authentication for the service.
        """
        release_name = self.config.ingress.oidc.release_name_template.format(
            service_name = service.name
        )
        cookie_secret = await self._reconcile_oidc_cookie_secret(client, service)
        config, config_checksum = self._oauth2_proxy_alpha_config(
            issuer_url,
            client_id,
            client_secret,
            allowed_groups
        )
        # Work out if we are running under a secure connection
        secure = self.config.ingress.tls.enabled or "tls-cert" in service.config
        # Ensure that the OAuth2 proxy release exists
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
                "alphaConfig": {
                    "enabled": True,
                    "configData": config,
                },
                "config": {
                    "configFile": "",
                },
                "podAnnotations": {
                    "checksum/config-alpha": config_checksum,
                },
                "proxyVarsAsSecrets": False,
                "extraArgs": {
                    "proxy-prefix": self.config.ingress.oidc.oauth2_proxy_path_prefix,
                    "cookie-secret": cookie_secret,
                    "cookie-expire": self.config.ingress.oidc.oauth2_proxy_cookie_lifetime,
                    "cookie-refresh": self.config.ingress.oidc.oauth2_proxy_cookie_refresh,
                    # If the ingress is not using TLS, we have to allow the cookie on insecure connections
                    "cookie-secure": "true" if secure else "false",
                    "whitelist-domain": service_domain,
                    "email-domain": "*",
                    "redirect-url": "{scheme}://{host}{prefix}/callback".format(
                        scheme = "https" if secure else "http",
                        prefix = self.config.ingress.oidc.oauth2_proxy_path_prefix,
                        host = service_domain
                    ),
                    "silence-ping-logging": "true",
                    # Skip the "proceed to provider" screen on a re-authenticate
                    "skip-provider-button": "true",
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
        # Create the ingresses
        await self._reconcile_oidc_ingress(
            release_name,
            client,
            service,
            service_domain,
            ingress_modifier
        )
        # Return the auth details for the main ingress
        return (
            "http://{name}.{namespace}.{domain}{prefix}/auth".format(
                name = release_name,
                namespace = self.config.target_namespace,
                domain = self.config.cluster_services_domain,
                prefix = self.config.ingress.oidc.oauth2_proxy_path_prefix
            ),
            "{scheme}://{host}{prefix}/start??rd=$escaped_request_uri&$args".format(
                scheme = "https" if secure else "http",
                host = service_domain,
                prefix = self.config.ingress.oidc.oauth2_proxy_path_prefix
            ),
            # Copy the remote user and group headers from the auth response onto the main response
            ["X-Remote-User", "X-Remote-Group"],
            # oauth2-proxy uses cookie splitting for large OIDC tokens
            # Make sure that we copy a reasonable number of split cookies to the main response
            [f"_oauth2_proxy_{i}" for i in range(1, 4)],
        )

    async def _remove_oidc_proxy(self, client, service):
        """
        Removes the oauth2-proxy release and associated resources for the service.
        """
        release_name = self.config.ingress.oidc.release_name_template.format(
            service_name = service.name
        )
        # Remove the ingress first
        ingresses = await client.api("networking.k8s.io/v1").resource("ingresses")
        await ingresses.delete(release_name)
        # The the Helm release
        await self._helm_client.uninstall_release(
            release_name,
            namespace = self.config.target_namespace
        )
        # Then the cookie secret
        secrets = await client.api("v1").resource("secrets")
        secret_name = self.config.ingress.oidc.oauth2_proxy_cookie_secret_template.format(
            service_name = service.name
        )
        await secrets.delete(secret_name)

    async def _apply_auth(self, client, service, service_domain, ingress, ingress_modifier):
        """
        Apply any authentication configuration defined in the configuration and/or
        service to the ingress.
        """
        # Decide what authentication to apply
        # This is done with the following precedence:
        #   1. If the client opted out of auth, no auth is applied
        #   2. If the client specified OIDC credentials, use them
        #   3. If OIDC discovery is enabled, use that
        #      This allows an external controller to place secrets into the Zenith namespace
        #      containing OIDC credentials for each service
        #   4. If external auth is configured, use that
        #   5. No auth is applied
        skip_auth = service.config.get("skip-auth", False)
        use_oidc = (
            not skip_auth and (
                service.config.get("auth-oidc-issuer") or
                self.config.ingress.oidc.discovery_enabled
            )
        )
        use_external = not skip_auth and not use_oidc and self.config.ingress.external_auth.url
        # Apply/unapply OIDC authentication as required
        # Note that in the case where OIDC authentication is not enabled, we want to ensure that
        # the OIDC proxy components are gone
        if use_oidc:
            issuer_url, client_id, client_secret, allowed_groups = (
                await self._reconcile_oidc_credentials(
                    client,
                    service
                )
            )
            auth_url, signin_url, response_headers, cookies = await self._reconcile_oidc_proxy(
                client,
                service,
                service_domain,
                issuer_url,
                client_id,
                client_secret,
                allowed_groups,
                ingress_modifier
            )
            ingress_modifier.configure_authentication(
                ingress,
                auth_url,
                signin_url,
                response_headers = response_headers,
                response_cookies = cookies
            )
        else:
            await self._remove_oidc_proxy(client, service)
        if use_external:
            # Determine what headers to set/override on the auth request
            #   Start with the fixed defaults
            request_headers = dict(self.config.ingress.external_auth.request_headers)
            #   Then set additional headers from the external auth params
            request_headers.update({
                f"{self.config.ingress.external_auth.param_header_prefix}{name}": value
                for name, value in service.config.get("auth-external-params", {}).items()
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
        self._logger.info(f"Reconciling {service.name} [{endpoints}]")
        # First create or update the corresponding service
        await client.apply_object(
            self._adopt(
                service,
                {
                    "apiVersion": "v1",
                    "kind": "Service",
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
            ),
            force = True
        )
        # Then create or update the endpoints object
        await client.apply_object(
            self._adopt(
                service,
                {
                    "apiVersion": "v1",
                    "kind": "Endpoints",
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
            ),
            force = True
        )
        # Finally, create or update the ingress object
        service_domain = f"{service.name}.{self.config.ingress.base_domain}"
        ingress = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
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
                self._logger.warn("Given read timeout is not a valid integer")
            else:
                ingress_modifier.configure_read_timeout(ingress, read_timeout)
        # Apply any TLS configuration
        await self._apply_tls(client, service, service_domain, ingress, ingress_modifier)
        # Apply any auth configuration
        await self._apply_auth(client, service, service_domain, ingress, ingress_modifier)
        # Create or update the ingress
        await client.apply_object(self._adopt(service, ingress), force = True)

    async def _remove_service(self, client, name):
        """
        Removes a service from Kubernetes.
        """
        self._logger.info(f"Removing {name}")
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

    async def _populate_queue(self, client, source, queue):
        """
        Pushes service events from the given source onto the given queue.
        """
        initial_services, events, _ = await source.subscribe()
        # Before beginning to process events from the iterator, put events onto the queue
        # to reconcile the initial state
        services = await client.api("v1").resource("services")
        existing_services = {
            service["metadata"]["name"]
            async for service in services.list(labels = self._labels(PRESENT))
        }
        for service in initial_services:
            await queue.put(Event(EventKind.UPDATED, service))
        for name in existing_services.difference(s.name for s in initial_services):
            await queue.put(Event(EventKind.DELETED, Service(name)))
        # Then just push events from Consul onto the queue
        async for event in events:
            await queue.put(event)

    async def _consume_queue(self, client, queue, ingress_modifier):
        """
        Pulls service events off the queue and executes them in order, requeueing if necessary.
        """
        while True:
            event, retries = await queue.get()
            try:
                # When a service has no active endpoints, we want to remove it
                if event.kind == EventKind.DELETED or not event.service.endpoints:
                    await self._remove_service(client, event.service.name)
                else:
                    await self._reconcile_service(client, event.service, ingress_modifier)
            except Exception:
                self._logger.exception(f"Error reconciling service '{event.service.name}'")
                queue.requeue(event, retries)

    async def run(self, source):
        """
        Run the reconciler against services from the given service source.
        """
        self._logger.info(f"Reconciling services [namespace: {self.config.target_namespace}]")
        client = ekconfig.async_client(
            default_field_manager = self.config.easykube_field_manager,
            default_namespace = self.config.target_namespace
        )
        async with client:
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
            # Create the queue that we will use to process events
            queue = EventQueue(self.config.reconciliation_max_backoff)
            # If there are no problems, the queue populator and queue consumer will run forever
            # So wait for the first one to exit, then make sure any exceptions are raised
            done, not_done = await asyncio.wait(
                [
                    self._populate_queue(client, source, queue),
                    self._consume_queue(client, queue, ingress_modifier),
                ],
                return_when = asyncio.FIRST_COMPLETED
            )
            for task in not_done:
                task.cancel()
            for task in done:
                task.result()


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
        await client.apply_object(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": self.config.ingress.tls.secret_name,
                    "namespace": self.config.target_namespace,
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
            force = True
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
            client = ekconfig.async_client(default_field_manager = self.config.easykube_field_manager)
            async with client:
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
