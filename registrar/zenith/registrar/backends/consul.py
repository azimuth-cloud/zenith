import base64
import typing as t

import httpx

from .. import config

from . import base


def fingerprint_urlsafe(fingerprint: bytes) -> str:
    return base64.urlsafe_b64encode(fingerprint).decode().rstrip("=")


class Backend(base.Backend):
    """
    Registrar backend that stores service information in Consul.
    """
    def __init__(self, consul_url: str, key_prefix: str):
        self.client = httpx.AsyncClient(base_url = consul_url)
        self.key_prefix = key_prefix

    async def reserve_subdomain(self, subdomain: str) -> str:
        response = await self.client.put(
            "/v1/txn",
            # Create the subdomain record with a value of 0
            # Use a CAS operation with an index of 0 to ensure that we are the
            # creators of the record
            json = [
                {
                    "KV": {
                        "Verb": "cas",
                        "Index": 0,
                        "Key": f"{self.key_prefix}/subdomains/{subdomain}",
                        "Value": base64.b64encode(b"0").decode(),
                    },
                },
            ]
        )
        # If the subdomain already exists, the response will be a 409
        if response.status_code == 409:
            raise base.SubdomainAlreadyReserved(subdomain)
        response.raise_for_status()
        # If we get to here, the domain was registered successfully
        # The index we return is the Consul modify index for the record
        return str(response.json()["Results"][0]["KV"]["ModifyIndex"])

    async def init_subdomain(
        self,
        subdomain: str,
        index: str,
        fingerprints: t.Iterable[bytes]
    ):
        # Use a transaction to update the subdomain record and pubkey records atomically
        response = await self.client.put("/v1/txn", json = [
            {
                "KV": {
                    # Use a check-and-set (cas) operation with the index to update the
                    # value of the subdomain key from zero to one
                    # In this way, we can be sure that we are the first operation to do this
                    "Verb": "cas",
                    "Index": int(index),
                    "Key": f"{self.key_prefix}/subdomains/{subdomain}",
                    "Value": base64.b64encode(b"1").decode(),
                },
            },
        ] + [
            {
                "KV": {
                    # Use regular set operations here, as we don't care about splatting existing
                    # pubkey records (it shouldn't happen with a well-behaved client anyway)
                    "Verb": "set",
                    # Use a URL-safe fingerprint as the key, otherwise any "/" characters form a
                    # nested structure that we don't want
                    "Key": f"{self.key_prefix}/pubkeys/{fingerprint_urlsafe(fingerprint)}",
                    # The value is the subdomain, which can be looked up by key later
                    "Value": base64.b64encode(subdomain.encode()).decode(),
                }
            }
            for fingerprint in fingerprints
        ])
        # If the subdomain already exists, the response will be a 409
        if response.status_code == 409:
            raise base.SubdomainAlreadyInitialised(subdomain)
        response.raise_for_status()

    async def subdomain_for_public_key(self, fingerprint: bytes) -> str:
        # Try to read a KV entry for the fingerprint
        url = f"/v1/kv/{self.key_prefix}/pubkeys/{fingerprint_urlsafe(fingerprint)}"
        response = await self.client.get(url)
        # Report a specific error if we get a 404
        if response.status_code == 404:
            raise base.PublicKeyNotAssociated(fingerprint)
        response.raise_for_status()
        # The response will contain a list, we should take the first item
        # The value should be in the item, base64-encoded
        return base64.b64decode(response.json()[0]["Value"]).decode()

    async def startup(self):
        await self.client.__aenter__()

    async def shutdown(self):
        await self.client.__aexit__(None, None, None)

    @classmethod
    def from_config(cls, config_obj: config.RegistrarConfig) -> "Backend":
        """
        Initialises an instance of the backend from a config object.
        """
        return cls(config_obj.consul_url, config_obj.consul_key_prefix)
