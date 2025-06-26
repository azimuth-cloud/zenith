import datetime
import logging
import typing as t

from easykube import ApiError, Configuration

from .. import config  # noqa: TID252
from . import base


class MaximumNumberOfEndpointsExceeded(Exception):  # noqa: N818
    """
    Raised when the maximum number of endpoints has been exceeded.
    """


def isotime() -> str:
    """
    Returns the current time as an ISO8601 formatted string.
    """
    return datetime.datetime.now(tz=datetime.timezone.utc).isoformat(timespec="seconds")


class Backend(base.Backend):
    """
    SSHD backend that stores information using CRD instances.
    """

    def __init__(
        self,
        logger: logging.Logger,
        api_version: str,
        target_namespace: str,
        max_endpoints: int,
    ):
        self.logger = logger
        self.api_version = api_version
        # Initialise an easykube client from the environment
        self.ekclient = Configuration.from_environment().sync_client(
            default_namespace=target_namespace
        )
        self.max_endpoints = max_endpoints

    def tunnel_check_host_and_port(self, host: str, port: int) -> bool:
        ekendpoints = self.ekclient.api(self.api_version).resource("endpoints")
        for endpoints in ekendpoints.list():
            for endpoint in endpoints.get("spec", {}).get("endpoints", {}).values():
                if endpoint["address"] == host and endpoint["port"] == port:
                    return False
        return True

    def tunnel_init(
        self,
        subdomain: str,
        host: str,
        port: int,
        ttl: int,
        reap_after: int,
        config_dict: dict[str, t.Any],
    ) -> str:
        # Fetch the service resource, so that it can own the endpoints resource
        # It also means we fail early if something has gone awry with the registrar
        ekservices = self.ekclient.api(self.api_version).resource("services")
        service = ekservices.fetch(subdomain)

        # Get the endpoints record, so that it can own our lease
        # If it doesn't exist, create it
        ekendpoints = self.ekclient.api(self.api_version).resource("endpoints")
        try:
            endpoints = ekendpoints.fetch(subdomain)
        except ApiError as exc:
            if exc.status_code == 404:
                # Fetch the service so it can own the endpoints resource
                endpoints = ekendpoints.create(
                    {
                        "metadata": {
                            "name": service["metadata"]["name"],
                            "namespace": service["metadata"]["namespace"],
                            "ownerReferences": [
                                {
                                    "apiVersion": service["apiVersion"],
                                    "kind": service["kind"],
                                    "name": service["metadata"]["name"],
                                    "uid": service["metadata"]["uid"],
                                    "blockOwnerDeletion": True,
                                },
                            ],
                        }
                    }
                )
            else:
                raise

        # If the endpoints resource is already full, fail
        # A well-behaved client should retry until it can be fitted in
        if len(endpoints.get("spec", {}).get("endpoints", {})) >= self.max_endpoints:
            raise MaximumNumberOfEndpointsExceeded

        # Create a lease for the tunnel
        ekleases = self.ekclient.api(self.api_version).resource("leases")
        lease = ekleases.create(
            {
                "metadata": {
                    # Generate a name based on the subdomain
                    # We will use this as the tunnel ID
                    "generateName": f"{subdomain}-",
                    "ownerReferences": [
                        {
                            "apiVersion": endpoints["apiVersion"],
                            "kind": endpoints["kind"],
                            "name": endpoints["metadata"]["name"],
                            "uid": endpoints["metadata"]["uid"],
                            "blockOwnerDeletion": True,
                        },
                    ],
                },
                "spec": {
                    "renewedAt": isotime(),
                    "ttl": ttl,
                    "reapAfter": reap_after,
                },
            }
        )

        # The tunnel ID is the lease name with the subdomain prefix removed
        tunnel_id = lease["metadata"]["name"].removeprefix(f"{subdomain}-")

        # Update the endpoints resource with the endpoint definition
        # The endpoints resource should already exist
        ekendpoints.patch(
            subdomain,
            {
                "spec": {
                    "endpoints": {
                        tunnel_id: {
                            "address": host,
                            "port": port,
                            # The initial status is critical, until the first heartbeat
                            "status": base.TunnelStatus.CRITICAL.value,
                            "config": config_dict,
                        },
                    },
                },
            },
        )

        return tunnel_id

    def tunnel_heartbeat(self, subdomain: str, id: str, status: base.TunnelStatus):  # noqa: A002
        # Renew the lease
        self.ekclient.api(self.api_version).resource("leases").patch(
            f"{subdomain}-{id}",
            {
                "spec": {
                    "renewedAt": isotime(),
                },
            },
        )
        # Update the endpoint status
        self.ekclient.api(self.api_version).resource("endpoints").patch(
            subdomain,
            {
                "spec": {
                    "endpoints": {
                        id: {
                            "status": status.value,
                        },
                    },
                },
            },
        )

    def tunnel_terminate(self, subdomain: str, id: str):  # noqa: A002
        # Remove the tunnel from the endpoints object
        self.ekclient.api(self.api_version).resource("endpoints").json_patch(
            subdomain,
            [
                {
                    "op": "remove",
                    "path": f"/spec/endpoints/{id}",
                },
            ],
        )
        # Delete the lease
        self.ekclient.api(self.api_version).resource("leases").delete(
            f"{subdomain}-{id}"
        )

    def startup(self):
        self.ekclient.__enter__()

    def shutdown(self):
        self.ekclient.__exit__(None, None, None)

    @classmethod
    def from_config(
        cls, logger: logging.Logger, config_obj: config.SSHDConfig
    ) -> "Backend":
        """
        Initialises an instance of the backend from a config object.
        """
        return Backend(
            logger,
            config_obj.crd_api_version,
            config_obj.crd_target_namespace,
            config_obj.crd_max_endpoints,
        )
