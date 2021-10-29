import asyncio
import contextlib
import importlib.metadata
import logging

import httpx

from .config import CertManagerIssuerType
from .model import EventKind
from .ingress_modifier import INGRESS_MODIFIERS_ENTRY_POINT_GROUP


logger = logging.getLogger(__name__)


class KubernetesApiError(Exception):
    """
    Exception that is raised when a Kubernetes API error occurs that is in the 4xx range.
    """
    def __init__(self, data):
        self.data = data
        super().__init__(data.get("message", str(data)))


class KubernetesClient(httpx.AsyncClient):
    """
    Custom HTTPX client for Kubernetes.

    Assumes that "kubectl proxy" is providing access to the API server.
    """
    def __init__(self, *, default_namespace = "default", **kwargs):
        self.default_namespace = default_namespace
        super().__init__(base_url = "http://127.0.0.1:8001", **kwargs)

    def _merge_url(self, url):
        # Replace the namespace in the URL if specified
        if isinstance(url, httpx.URL):
            url = str(url)
        return super()._merge_url(url.format(namespace = self.default_namespace))

    async def request(self, *args, **kwargs):
        # Make requests raise exceptions for bad responses
        response = await super().request(*args, **kwargs)
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if 400 <= exc.response.status_code < 500:
                raise KubernetesApiError(exc.response.json())
            else:
                raise
        else:
            return response

    @contextlib.asynccontextmanager
    async def suppress_api_exception(self, status_code, reason = None):
        """
        Context manager that suppresses exceptions raised by the Kubernetes client
        with the given status code and optional reason.
        """
        try:
            yield
        except KubernetesApiError as exc:
            # If the status doesn't match, re-raise the exception
            if exc.data.get("code") != status_code:
                raise
            # If a reason was given, check if it matches the reason from the exception
            # and re-raise it if not
            if reason and reason != exc.data.get("reason"):
                raise
            # If we get to here, the exception is suppressed

    @contextlib.asynccontextmanager
    async def suppress_not_found(self):
        """
        Context manager that suppresses the notfound raised by the Kubernetes client when
        attempting to fetch, modify or delete a resource that doesn't exist.
        """
        async with self.suppress_api_exception(404):
            yield

    @contextlib.asynccontextmanager
    async def suppress_already_exists(self):
        """
        Context manager that suppresses the conflict raised by the Kubernetes client when
        attempting to create a resource that already exists.
        """
        async with self.suppress_api_exception(409, "AlreadyExists"):
            yield


class KubernetesResource:
    """
    Base class for a Kubernetes resource.
    """
    def __init__(self, client):
        self.client = client

    def _path(self, *, namespace = None, name = None):
        """
        Return the URL for the resource, or resource instance if name is specified.
        """
        path = f"{self.base_path}/{name}" if name else self.base_path
        # If a namespace has been given, override any namespace in the path
        return path.format(namespace = namespace) if namespace else path

    async def list(self, *, namespace = None, labels = None):
        """
        Returns a list of resource instances that match the given labels. 
        """
        params = {}
        if labels:
            params["labelSelector"] = ",".join(f"{k}={v}" for k, v in labels.items())
        resp = await self.client.get(self._path(namespace = namespace), params = params)
        return resp.json()["items"]

    async def one(self, *, namespace = None, labels = None):
        """
        Returns the first resource instance that matches the given labels,
        or None if no instances are returned.
        """
        return next(iter(await self.list(namespace = namespace, labels = labels)))

    async def get(self, name, *, namespace = None):
        """
        Returns the named instance of the resource, or raises an error if it
        does not exist.
        """
        path = self._path(namespace = namespace, name = name)
        resp = await self.client.get(path)
        return resp.json()

    async def create(self, body, *, namespace = None):
        """
        Creates an instance of the resource.
        """
        # Make sure the api version and kind are correct in the body
        body.update({ "apiVersion": self.api_version, "kind": self.kind })
        # Use the namespace from the body if specified
        namespace = namespace or body.get("metadata", {}).get("namespace")
        resp = await self.client.post(self._path(namespace = namespace), json = body)
        return resp.json()

    async def patch(self, body, *, namespace = None, name = None):
        """
        Patches an instance of the resource.
        """
        # Get the namespace and name from the metadata if not given
        metadata = body.get("metadata")
        namespace = namespace or metadata.get("namespace")
        name = name or metadata.get("name")
        if not name:
            raise ValueError("name must be specified either directly or via body.metadata")
        path = self._path(namespace = namespace, name = name)
        resp = await self.client.patch(
            path,
            json = body,
            headers = { "Content-Type": "application/merge-patch+json" }
        )
        return resp.json()

    async def create_or_patch(self, body, *, namespace = None):
        """
        Patches an instance of the resource or creates it if it doesn't exist.
        """
        async with self.client.suppress_already_exists():
            return await self.create(body, namespace = namespace)
        # If we get to here, a conflict was suppressed
        return await self.patch(body, namespace = namespace)

    async def delete(self, name, *, namespace = None):
        """
        Deletes an instance of the resource.
        """
        path = self._path(namespace = namespace, name = name)
        await self.client.delete(path)

    async def delete_all(self, *, namespace = None, labels = None):
        """
        Deletes all the instances of the resource that match the given labels.
        """
        params = {}
        if labels:
            params["labelSelector"] = ",".join(f"{k}={v}" for k, v in labels.items())
        await self.client.delete(self._path(namespace = namespace), params = params)

    @classmethod
    def make(cls, api_version, kind, plural = None, namespaced = True):
        """
        Creates a new resource subclass.
        """
        # Calculate the plural from the kind if not given
        plural = plural or f"{kind.lower()}s"
        # Calculate the base path for the resource
        path_parts = ["api" if api_version == "v1" else "apis", api_version]
        if namespaced:
            path_parts.extend(["namespaces", "{namespace}"])
        path_parts.append(plural)
        base_path = "/".join(path_parts)
        return type(
            kind,
            (cls, ),
            dict(
                api_version = api_version,
                kind = kind,
                plural = plural,
                namespaced = namespaced,
                base_path = base_path
            )
        )


Endpoints = KubernetesResource.make("v1", "Endpoints", "endpoints")
Secret = KubernetesResource.make("v1", "Secret")
Service = KubernetesResource.make("v1", "Service")
Ingress = KubernetesResource.make("networking.k8s.io/v1", "Ingress", "ingresses")
IngressClass = KubernetesResource.make(
    "networking.k8s.io/v1",
    "IngressClass",
    "ingressclasses",
    namespaced = False
)


class ServiceReconciler:
    """
    Reconciles headless services in Kubernetes with information from
    another system.
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

    async def _reconcile_service(self, client, service, ingress_modifier):
        """
        Reconciles a service with Kubernetes.
        """
        endpoints = ", ".join(f"{ep.address}:{ep.port}" for ep in service.endpoints)
        self._log("info", f"Reconciling {service.name} [{endpoints}]")
        # First create or update the corresponding service
        await Service(client).create_or_patch(
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
        await Endpoints(client).create_or_patch(
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
                "annotations": dict(self.config.ingress.annotations),
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
        # Apply ingress-specific modifications for the backend protocol
        protocol = service.metadata.get("backend-protocol", "http")
        ingress_modifier.configure_backend_protocol(ingress, protocol)
        # Add a TLS section if required
        tls_secret_name = None
        if "tls-cert" in service.tls:
            # If the service specified a TLS certificate, that takes precedence
            # Make a secret with the certificate in to pass to the ingress
            tls_secret_name = f"tls-{service.name}"
            await Secret(client).create_or_patch(
                self._adopt(
                    service,
                    {
                        "metadata": {
                            "name": tls_secret_name,
                        },
                        "type": "kubernetes.io/tls",
                        "data": {
                            "tls.crt": service.tls["tls-cert"],
                            "tls.key": service.tls["tls-key"],
                        },
                    }
                )
            )
        elif self.config.ingress.tls.wildcard_secret_name:
            # If a wildcard certificate was given, use that next
            tls_secret_name = self.config.ingress.tls.wildcard_secret_name
        elif self.config.ingress.tls.cert_manager_issuer_name:
            # Configure a cert-manager issuer if specified
            # cert-manager will put the TLS certificate and key in this secret
            tls_secret_name = f"tls-{service.name}"
            if self.config.ingress.tls.cert_manager_issuer_type == CertManagerIssuerType.CLUSTER:
                issuer_annotation = "cert-manager.io/cluster-issuer"
            else:
                issuer_annotation = "cert-manager.io/issuer"
            issuer_name = self.config.ingress.tls.cert_manager_issuer_name
            ingress["metadata"]["annotations"][issuer_annotation] = issuer_name
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
            await Secret(client).create_or_patch(
                self._adopt(
                    service,
                    {
                        "metadata": {
                            "name": client_ca_secret,
                        },
                        "data": {
                            "ca.crt": service.tls["tls-client-ca"]
                        }
                    }
                )
            )
            # Apply ingress-specific modifications for client certificate handling
            ingress_modifier.configure_tls_client_certificates(
                ingress,
                self.config.namespace,
                client_ca_secret
            )
        # Create or update the ingress
        await Ingress(client).create_or_patch(self._adopt(service, ingress))

    async def _remove_service(self, client, name):
        """
        Removes a service from Kubernetes.
        """
        self._log("info", f"Removing {name}")
        # We have to delete the corresponding endpoints, service and ingress objects
        async with client.suppress_not_found():
            await Ingress(client).delete(name)
        async with client.suppress_not_found():
            await Endpoints(client).delete(name)
        async with client.suppress_not_found():
            await Service(client).delete(name)
        # Also delete any secrets created for the service
        # This will leave behind secrets created by cert-manager, which is fine because
        # it means that if a reconnection occurs for the same domain it will be a
        # renewal which doesn't count towards the rate limit
        await Secret(client).delete_all(labels = self._labels(name))

    async def run(self, source):
        """
        Run the reconciler against services from the given service source.
        """
        client = KubernetesClient(default_namespace = self.config.namespace)
        logger.info(
            "Initialised Kubernetes client [server: %s, default_namespace: %s]",
            client.base_url,
            client.default_namespace
        )
        async with client:
            # Before we process the service, retrieve information about the ingress class
            # we are using
            ingress_class = await IngressClass(client).get(self.config.ingress.class_name)
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
            services = await Service(client).list()
            existing_services = set(s["metadata"]["name"] for s in services)
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
