import logging
import typing as t

import requests

from .. import config

from . import base


class Backend(base.Backend):
    """
    SSHD backend that stores service information in Consul.
    """
    def __init__(
        self,
        logger: logging.Logger,
        url: str,
        key_prefix: str,
        service_tag: str
    ):
        self.logger = logger
        self.url = url
        self.key_prefix = key_prefix
        self.service_tag = service_tag

    def tunnel_check_host_and_port(self, host: str, port: int) -> bool:
        response = requests.get(
            f"{self.url}/v1/agent/services",
            params = dict(
                filter = (
                    f"Address == \"{host}\" and "
                    f"Port == \"{port}\" and "
                    f"\"{self.service_tag}\" in Tags"
                )
            )
        )
        response.raise_for_status()
        return not response.json()

    def tunnel_init(
        self,
        subdomain: str,
        host: str,
        port: int,
        ttl: int,
        reap_after: int,
        config_dict: t.Dict[str, t.Any]
    ) -> str:
        # Start a Consul session for the tunnel
        self.logger.debug("Starting Consul session for tunnel")
        response = requests.put(
            f"{self.url}/v1/session/create",
            json = {
                # Delete keys held by the session when the TTL expires
                "Behavior": "delete",
                # The TTL for the session - we must renew the session within this limit
                "TTL": f"{ttl}s",
            }
        )
        response.raise_for_status()
        tunnel_id = response.json()["ID"]

        # Post the tunnel configuration to the KV store, associated with the session
        self.logger.debug("Posting configuration to Consul", extra = { "tunnelid": tunnel_id })
        url = "{consul_url}/v1/kv/{key_prefix}/{tunnel_id}?acquire={tunnel_id}".format(
            consul_url = self.url,
            key_prefix = self.key_prefix,
            tunnel_id = tunnel_id
        )
        response = requests.put(url, json = config_dict)
        response.raise_for_status()

        # Post the service information to Consul
        self.logger.debug("Registering service with Consul", extra = { "tunnelid": tunnel_id })
        response = requests.put(
            f"{self.url}/v1/agent/service/register",
            json = {
                # Use the tunnel ID as the unique id
                "ID": tunnel_id,
                # Use the specified subdomain as the service name
                "Name": subdomain,
                # Use the service host and port as the address and port in Consul
                "Address": host,
                "Port": port,
                # Tag the service as a Zenith service
                "Tags": [self.service_tag],
                # Specify a TTL check
                "Check": {
                    # Use the unique ID for the tunnel as the check id
                    "CheckId": tunnel_id,
                    "Name": "tunnel-active",
                    # Use a TTL health check
                    # This will move into the critical state, removing the service from
                    # the proxy, if we do not post a status update within the TTL
                    "TTL": f"{ttl}s",
                    # This deregisters the service once it has been critical for the specified interval
                    # We can probably assume the service will not come back up
                    "DeregisterCriticalServiceAfter": f"{reap_after}s",
                },
            }
        )
        response.raise_for_status()

        # Return the tunnel ID
        return tunnel_id

    def tunnel_heartbeat(self, subdomain: str, id: str, status: base.TunnelStatus):
        self.logger.debug("Renewing Consul session")
        response = requests.put(f"{self.url}/v1/session/renew/{id}")
        response.raise_for_status()

        self.logger.debug(f"Updating Consul service status to '{status.value}'")
        url = f"{self.url}/v1/agent/check/update/{id}"
        response = requests.put(url, json = { "Status": status.value })
        response.raise_for_status()

    def tunnel_terminate(self, subdomain: str, id: str):
        """
        Terminate the specified tunnel.
        """
        self.logger.debug("Removing service from Consul")
        requests.put(f"{self.url}/v1/agent/service/deregister/{id}")
        self.logger.debug("Removing configuration from Consul KV")
        requests.delete(f"{self.url}/v1/kv/{self.key_prefix}/{id}")
        self.logger.debug("Terminating Consul session")
        requests.put(f"{self.url}/v1/session/destroy/{id}")

    @classmethod
    def from_config(cls, logger: logging.Logger, config_obj: config.SSHDConfig) -> "Backend":
        """
        Initialises an instance of the backend from a config object.
        """
        return Backend(
            logger,
            config_obj.consul_url,
            config_obj.consul_key_prefix,
            config_obj.consul_service_tag
        )
