import asyncio
import base64
import dataclasses
import json
import logging
import random
import os

from easykube import Configuration, ApiError, PRESENT

from pyhelm3 import Client as HelmClient

from .model import Event, EventKind, Service


# Initialise the easykube config from the environment
ekconfig = Configuration.from_environment()


class RetryRequired(Exception):
    """
    Raised to explicitly request a retry with a warning message.
    """


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
        try:
            secret = await secrets.fetch(
                self.config.ingress.oidc.discovery_secret_name_template.format(
                    service_name = service.name
                )
            )
        except ApiError as exc:
            if exc.status_code == 404:
                raise RetryRequired("oidc discovery secret not available")
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
                    force = True
                )
            else:
                raise
        return base64.b64decode(secret.data["cookie-secret"]).decode()

    def _get_service_values(self, service):
        """
        Returns the values for the core service configuration.
        """
        # Build the core values for the service
        values = {
            "global": {
                "domain": f"{service.name}.{self.config.ingress.base_domain}",
            },
            "endpoints": [dataclasses.asdict(ep) for ep in service.endpoints],
            "protocol": service.config.get("backend-protocol", "http"),
        }
        read_timeout = service.config.get("read-timeout")
        if read_timeout:
            # Check that the read timeout is an int - if it isn't don't use it
            try:
                read_timeout = int(read_timeout)
            except ValueError:
                self._logger.warn("Given read timeout is not a valid integer")
            else:
                values["readTimeout"] = read_timeout
        return values

    def _get_tls_values(self, service):
        """
        Returns the values for configuring the TLS for a service.
        """
        tls_enabled = self.config.ingress.tls.enabled or "tls-cert" in service.config
        values = { "global": { "secure": tls_enabled }}
        if not tls_enabled:
            return values
        tls_values = values.setdefault("ingress", {}).setdefault("tls", {})
        tls_values["annotations"] = self.config.ingress.tls.annotations
        tls_values["secretName"] = self.config.ingress.tls.secret_name
        if "tls-cert" in service.config:
            tls_values["existingCertificate"] = {
                "cert": service.config["tls-cert"],
                "key": service.config["tls-key"],
            }
        if "tls-client-ca" in service.config:
            tls_values["clientCA"] = service.config["tls-client-ca"]
        return values
    
    async def _get_auth_values(self, client, service):
        """
        Returns the values for configuring the auth for a service.

        This may involve querying and/or creating secrets.
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
        values = {}
        if service.config.get("skip-auth", False):
            values["oidc"] = { "enabled": False }
            values["externalAuth"] = { "enabled": False }
        elif (
            service.config.get("auth-oidc-issuer") or
            self.config.ingress.oidc.discovery_enabled
        ):
            issuer_url, client_id, client_secret, allowed_groups = (
                await self._reconcile_oidc_credentials(
                    client,
                    service
                )
            )
            cookie_secret = await self._reconcile_oidc_cookie_secret(client, service)
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

    async def _reconcile_service(self, client, service):
        """
        Reconciles a service with Kubernetes.
        """
        endpoints = ", ".join(f"{ep.address}:{ep.port}" for ep in service.endpoints)
        self._logger.info(f"Reconciling {service.name} [{endpoints}]")
        # Install the Helm release
        _ = await self._helm_client.ensure_release(
            service.name,
            await self._helm_client.get_chart(
                self.config.service_chart_name,
                repo = self.config.service_chart_repo,
                version = self.config.service_chart_version
            ),
            self.config.service_default_values,
            self._get_service_values(service),
            self._get_tls_values(service),
            await self._get_auth_values(client, service),
            cleanup_on_fail = True,
            # The namespace should exist, so we don't need to create it
            create_namespace = False,
            namespace = self.config.target_namespace,
            # Wait for the components to become ready
            wait = True
        )

    async def _remove_service(self, client, name):
        """
        Removes a service from Kubernetes.
        """
        self._logger.info(f"Removing {name}")
        # Remove the Helm release for the service
        await self._helm_client.uninstall_release(
            name,
            namespace = self.config.target_namespace,
            wait = True
        )
        # Delete the OIDC cookie secret if required
        secrets = await client.api("v1").resource("secrets")
        secret_name = self.config.ingress.oidc.oauth2_proxy_cookie_secret_template.format(
            service_name = name
        )
        await secrets.delete(secret_name)

    async def _next_event(self, events):
        """
        Returns the next event from the event queue.
        """
        return await events.get()

    async def _wait_for_retry(self, retries):
        """
        Waits with an exponential backoff based on the number of retries.
        """
        backoff = 2**retries + random.uniform(0, 1)
        clamped_backoff = min(backoff, self.config.reconciliation_max_backoff)
        await asyncio.sleep(clamped_backoff)
        return retries + 1

    async def _process_event(self, client, event):
        """
        Processes a single event from the queue, with retries.
        """
        retries = 0
        while True:
            try:
                # When a service has no active endpoints, we want to remove it
                if event.kind == EventKind.DELETED or not event.service.endpoints:
                    await self._remove_service(client, event.service.name)
                else:
                    await self._reconcile_service(client, event.service)
            except RetryRequired as exc:
                # If a retry is explicitly requested, just issue a warning
                self._logger.warning(
                    "Retry required for %s event for %s - %s",
                    event.kind.name,
                    event.service.name,
                    str(exc)
                )
                # If a retry is explicitly requested then retry after a backoff
                retries = await self._wait_for_retry(retries)
            except Exception:
                self._logger.exception(
                    "Error processing %s event for %s",
                    event.kind.name,
                    event.service.name
                )
                # We want to retry after a backoff
                retries = await self._wait_for_retry(retries)
            except asyncio.CancelledError:
                self._logger.info(
                    "Processing of %s event for %s was cancelled",
                    event.kind.name,
                    event.service.name
                )
                raise
            else:
                self._logger.info(
                    "Reconciled %s event for %s successfully",
                    event.kind.name,
                    event.service.name
                )
                # If the event was processed successfully, we are done
                return event.service.name

    async def _step(self, client, events, next_event_task, service_tasks):
        """
        Performs a single execution step.
        """
        self._logger.info("Waiting for next task to complete")
        # Wait for the first task to complete
        tasks = set([next_event_task]).union(service_tasks.values())
        done, _ = await asyncio.wait(tasks, return_when = asyncio.FIRST_COMPLETED)
        self._logger.info("Processing %d completed tasks", len(done))
        # Adjust the tasks for the next step as required
        for completed_task in done:
            if completed_task == next_event_task:
                self._logger.info("Next event task completed")
                # We have received a new event
                event = completed_task.result()
                self._logger.info(
                    "Received %s event for %s",
                    event.kind.name,
                    event.service.name
                )
                # First, cancel any running task for the same service
                existing_task = service_tasks.pop(event.service.name, None)
                if existing_task and not existing_task.done():
                    self._logger.info("Cancelling existing task for %s", event.service.name)
                    existing_task.cancel()
                    # Wait for the task to actually finish cancelling
                    try:
                        await asyncio.wait_for(existing_task, 10)
                    except asyncio.CancelledError:
                        pass
                self._logger.info(
                    "Registering task to process %s event for %s",
                    event.kind.name,
                    event.service.name
                )
                # Create a new task to watch for the next event
                next_event_task = asyncio.create_task(self._next_event(events))
                # Register a task to process the new event
                coro = self._process_event(client, event)
                service_tasks[event.service.name] = asyncio.create_task(coro)
            else:
                self._logger.info("Event processing task completed")
                service_name = completed_task.result()
                self._logger.info("Event processing task completed for %s", service_name)
                # It is possible that the task has been replaced by the code above
                # So check for that and only pop the task if it is completed
                if service_tasks[service_name].done():
                    self._logger.info(
                        "Discarding completed processing task for %s",
                        service_name
                    )
                    service_tasks.pop(service_name)
        return next_event_task, service_tasks
    
    def _client(self):
        """
        Returns an easykube client configured for the target namespace.
        """
        return ekconfig.async_client(
            default_field_manager = self.config.easykube_field_manager,
            default_namespace = self.config.target_namespace
        )

    # TODO(mkjpryor)
    # deprecate and remove this method once all deployments have been upgraded
    async def _remove_legacy_resources(self, client):
        """
        Removes legacy resources from pre-Helm days.
        """
        # We can detect legacy resources because they will have the label that indicates
        # they were created by zenith-sync rather than Helm
        labels = { self.config.created_by_label: "zenith-sync" }

        self._logger.info("Removing legacy ingresses")
        ingresses = await client.api("networking.k8s.io/v1").resource("ingresses")
        await ingresses.delete_all(labels = labels)

        self._logger.info("Removing legacy endpoints")
        endpoints = await client.api("v1").resource("endpoints")
        await endpoints.delete_all(labels = labels)

        self._logger.info("Removing legacy services")
        services = await client.api("v1").resource("services")
        await services.delete_all(labels = labels)

        # For secrets, we want to be a little more particular and leave behind
        # the cookie secrets, which are still managed by zenith-sync
        # Deleting the cookie secrets here would mean that all the OIDC proxy sessions
        # would become invalidated every time zenith-sync restarts
        self._logger.info("Removing legacy secrets")
        secrets = await client.api("v1").resource("secrets")
        async for secret in secrets.list(labels = labels):
            if "cookie-secret" not in secret.data:
                await secrets.delete(secret.metadata.name)

        # We also want to remove all the Helm releases for OIDC proxies, as these are
        # now provisioned as part of the zenith-service chart
        self._logger.info("Removing legacy Helm releases")
        target_chart = await self._helm_client.get_chart(
            self.config.service_chart_name,
            repo = self.config.service_chart_repo,
            version = self.config.service_chart_version
        )
        releases = await self._helm_client.list_releases(
            all = True,
            max_releases = 0,
            namespace = self.config.target_namespace
        )
        for release in releases:
            revision = await release.current_revision()
            chart = await revision.chart_metadata()
            if chart.name != target_chart.metadata.name:
                await release.uninstall(wait = True)

    async def run(self, source):
        """
        Run the reconciler against services from the given service source.
        """
        self._logger.info(f"Reconciling services [namespace: {self.config.target_namespace}]")
        async with self._client() as client:
            # Before we start doing anything, we need to clean up legacy resources
            await self._remove_legacy_resources(client)
            # This dictionary stores a map of service names to the current task for the service
            service_tasks = {}
            initial_services, events, _ = await source.subscribe()
            # Before beginning to process events from the queue, schedule tasks to reconcile
            # the initial state
            releases = await self._helm_client.list_releases(
                all = True,
                max_releases = 0,
                namespace = self.config.target_namespace
            )
            existing_services = { release.name for release in releases }
            for service in initial_services:
                event = Event(EventKind.UPDATED, service)
                coro = self._process_event(client, event)
                service_tasks[service.name] = asyncio.create_task(coro)
            for name in existing_services.difference(s.name for s in initial_services):
                event = Event(EventKind.DELETED, Service(name))
                coro = self._process_event(client, event)
                service_tasks[name] = asyncio.create_task(coro)
            # Create a task to watch for the next event
            next_event_task = asyncio.create_task(self._next_event(events))
            while True:
                next_event_task, service_tasks = await self._step(
                    client,
                    events,
                    next_event_task,
                    service_tasks
                )


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
