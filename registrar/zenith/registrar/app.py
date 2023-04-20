import binascii
import base64
import hashlib
import hmac
import secrets
import string
import typing as t

from fastapi import FastAPI, Request, HTTPException

from httpx import AsyncClient

from .config import settings
from .models import (
    ReservationRequest,
    Reservation,
    PublicKeyAssociationRequest,
    PublicKeyAssociation,
    VerificationRequest,
    VerificationResult,
    Error
)


#: The FastAPI application
app = FastAPI()


def generate_random_subdomain():
    """
    Returns a random subdomain consisting of alphanumeric characters.

    The subdomain must be a valid Kubernetes service name, so must be at most 63 characters long,
    consist of lowercase letters, numbers and hyphens (-) only, and start with a letter.

    In addition, the FQDN (i.e. subdomain + base domain) must be at most 64 characters to fit
    in the CN of an SSL certificate when ACME issuing is used. Given that the base domain must be
    at least one character, plus a dot to separate the subdomain, this means that when a subdomain
    passes this test it automatically passes the length test for a Kubernetes service.
    """
    subdomain_len = min(
        # FQDN constraint: {subdomain}.{base_domain} must be at most 64 characters
        63 - len(settings.base_domain),
        # Absolute constraint, primarily to ensure valid Helm release names
        settings.subdomain_max_length
    )
    return "".join(
        # Domains must start with a letter
        [secrets.choice(string.ascii_lowercase)] +
        [
            # The rest of the characters are numbers or letters
            secrets.choice(string.ascii_lowercase + string.digits)
            for _ in range(subdomain_len - 1)
        ]
    )


def generate_signature(message: str) -> str:
    """
    Generates a signature for the given message using the signing key.
    """
    key = settings.subdomain_token_signing_key
    return hmac.new(key, message.encode(), hashlib.sha1).hexdigest()


def fingerprint_bytes(ssh_pubkey: str) -> bytes:
    """
    Returns the raw bytes for the fingerprint of an SSH public key.
    """
    data = binascii.a2b_base64(ssh_pubkey.split()[1])
    return hashlib.sha256(data).digest()


def fingerprint(ssh_pubkey: str) -> str:
    """
    Returns the fingerprint for an SSH public key.
    """
    digest = fingerprint_bytes(ssh_pubkey)
    return base64.b64encode(digest).decode().rstrip("=")


def fingerprint_urlsafe(ssh_pubkey: str) -> str:
    """
    Returns the fingerprint for an SSH public key.
    """
    digest = fingerprint_bytes(ssh_pubkey)
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


@app.post(
    "/admin/reserve",
    response_model = Reservation,
    responses = {
        409: {
            "description": "The subdomain has already been reserved.",
            "model": Error,
        },
    }
)
async def reserve_subdomain(request: Request, req: t.Optional[ReservationRequest] = None):
    """
    Reserve a subdomain for use with an application.

    If no subdomain is given, a random subdomain is reserved and returned.

    If a set of SSH public keys is given, they are associated with the subdomain and the
    fingerprints are returned. No token is returned in this case.

    If no SSH public keys are given, a single-use token is returned that can be used to
    associate public keys with the subdomain.
    """
    if not req:
        req = ReservationRequest()
    # Begin with the maximum number of attempts
    remaining_attempts = settings.generate_domain_max_attempts
    while remaining_attempts > 0:
        # As soon as we enter the loop, the remaining attempts decrease
        remaining_attempts = remaining_attempts - 1
        # Work out the subdomain that we will attempt to use
        subdomain = req.subdomain if req.subdomain is not None else generate_random_subdomain()
        # Work out what Consul operations we want to perform
        # We perform the operations within a Consul transaction to ensure atomicity
        # We use a check-and-set (CAS) operation with an index of zero for the subdomain record,
        # which means the operation will only succeed if it creates the key - this means a
        # subdomain can only be reserved once
        if req.public_keys:
            # If public keys are given, create the subdomain record with a value of 1
            # and create/update the public key associations at the same time
            # No token is returned
            operations = [
                {
                    "KV": {
                        "Verb": "cas",
                        "Index": 0,
                        "Key": f"{settings.consul_key_prefix}/subdomains/{subdomain}",
                        "Value": base64.b64encode(b"1").decode(),
                    },
                },
            ] + [
                {
                    "KV": {
                        # Use regular set operations to update the public key records, as we
                        # don't care about splatting existing records (a well-behaved client
                        # should generate a new keypair for each subdomain anyway)
                        "Verb": "set",
                        # Use a URL-safe fingerprint as the key, otherwise the "/" characters form a
                        # nested structure that we don't want
                        "Key": f"{settings.consul_key_prefix}/pubkeys/{fingerprint_urlsafe(pubkey)}",
                        # The value is the subdomain, which can be looked up by key later
                        "Value": base64.b64encode(subdomain.encode()).decode(),
                    }
                }
                for pubkey in req.public_keys
            ]
        else:
            # If no public keys are given, create the subdomain record with a value of 0
            # A token will be returned that contains the subdomain and the Consul modify index,
            # signed with a secret to ensure data integrity
            # The associate operation will then use the subdomain and modify index from the token
            # it receives to perform another CAS operation which changes the value of the
            # subdomain record from 0 to 1, registering the public keys at the same time
            # This operation will only succeed on the first attempt, making the tokens single use
            operations = [
                {
                    "KV": {
                        "Verb": "cas",
                        "Index": 0,
                        "Key": f"{settings.consul_key_prefix}/subdomains/{subdomain}",
                        "Value": base64.b64encode(b"0").decode(),
                    },
                },
            ]
        async with AsyncClient(base_url = settings.consul_url) as client:
            response = await client.put("/v1/txn", json = operations)
            # If the subdomain already exists, the response will be a 409
            # How we react to this depends on whether the request specified a subdomain or
            # if we generated one
            if response.status_code == 409:
                if req.subdomain is not None:
                    raise HTTPException(
                        status_code = 409,
                        detail = "The requested subdomain has already been reserved."
                    )
                else:
                    continue
            response.raise_for_status()
            # If we get to here, the domain was registered successfully and we should break out
            # after extracting the modify index
            # The response should be JSON with a single response
            modify_index = response.json()["Results"][0]["KV"]["ModifyIndex"]
            break
    else:
        # No subdomain allocated after maximum number of attempts
        raise HTTPException(
            status_code = 409,
            detail = "Unable to allocate a subdomain after {} attempts.".format(
                settings.generate_domain_max_attempts
            )
        )
    # The FQDN is the requests subdomain combined with the configured base domain
    fqdn = f"{subdomain}.{settings.base_domain}"
    if req.public_keys:
        # When the request contained public keys, return the fingerprints
        return Reservation(
            subdomain = subdomain,
            fqdn = fqdn,
            # Return non-URL-safe fingerprints so they can be compared with the output of OpenSSH
            fingerprints = [fingerprint(pubkey) for pubkey in req.public_keys]
        )
    else:
        # If no keys were given, return a signed token containing the subdomain and modify index
        token_data = f"{subdomain}.{modify_index}"
        signature = generate_signature(token_data)
        token = base64.urlsafe_b64encode(f"{token_data}.{signature}".encode()).decode()
        return Reservation(subdomain = subdomain, fqdn = fqdn, token = token)


@app.post(
    "/admin/verify",
    response_model = VerificationResult,
    responses = {
        404: {
            "description": "The given SSH public key is not known.",
            "model": Error,
        }
    }
)
async def verify_subdomain(req: VerificationRequest):
    """
    Verifies that the specified public key is permitted to use the specified subdomain.
    """
    # Try to read a KV entry for the fingerprint
    async with AsyncClient(base_url = settings.consul_url) as client:
        url = f"/v1/kv/{settings.consul_key_prefix}/pubkeys/{fingerprint_urlsafe(req.public_key)}"
        response = await client.get(url)
        # Report a specific error if we get a 404
        if response.status_code == 404:
            raise HTTPException(
                status_code = 404,
                detail = "The given SSH public key is not known."
            )
        response.raise_for_status()
        # The response will contain a list, we should take the first item
        # The value should be in the item, base64-encoded
        subdomain = base64.b64decode(response.json()[0]["Value"]).decode()
    return VerificationResult(subdomain = subdomain, public_key = req.public_key)


@app.post(
    "/associate",
    response_model = PublicKeyAssociation,
    responses = {
        400: {
            "description": "The given token is invalid.",
            "model": Error,
        },
        409: {
            "description": (
                "The given token has already been used or does not "
                "correspond to a reservation."
            ),
            "model": Error,
        },
    }
)
async def associate_public_keys(req: PublicKeyAssociationRequest):
    """
    Associate one or more public keys with the subdomain linked to the given token.
    """
    # Extract the token data and signature from the given token
    token_bytes = req.token.encode()
    try:
        decoded_token = base64.urlsafe_b64decode(token_bytes).decode()
        token_data, signature = decoded_token.rsplit(".", maxsplit = 1)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code = 400, detail = "The given token is invalid.")
    # Verify the signature matches the data
    if not hmac.compare_digest(generate_signature(token_data), signature):
        raise HTTPException(status_code = 400, detail = "The given token is invalid.")
    # Split the token data into subdomain and modify index
    try:
        subdomain, modify_index = token_data.split(".")
        modify_index = int(modify_index)
    except ValueError:
        raise HTTPException(status_code = 400, detail = "The given token is invalid.")
    # Get the fingerprint of each public key
    async with AsyncClient(base_url = settings.consul_url) as client:
        # Use a transaction to update the subdomain record and pubkey records atomically
        response = await client.put("/v1/txn", json = [
            {
                "KV": {
                    # Use a check-and-set (cas) operation to update the value of the subdomain
                    # key from zero to one
                    # By passing the modify index from the token, we can be sure that we are
                    # the first operation to do this, or the whole transaction will fail
                    "Verb": "cas",
                    "Index": modify_index,
                    "Key": f"{settings.consul_key_prefix}/subdomains/{subdomain}",
                    # Any value is fine, just to mark the domain as seen
                    "Value": base64.b64encode(b"1").decode(),
                },
            },
        ] + [
            {
                "KV": {
                    # Use regular set operations here, as we don't care about splatting existing
                    # pubkey records (it shouldn't happen with a well-behaved client anyway)
                    "Verb": "set",
                    # Use a URL-safe fingerprint as the key, otherwise the "/" characters form a
                    # nested structure that we don't want
                    "Key": f"{settings.consul_key_prefix}/pubkeys/{fingerprint_urlsafe(pubkey)}",
                    # The value is the subdomain, which can be looked up by key later
                    "Value": base64.b64encode(subdomain.encode()).decode(),
                }
            }
            for pubkey in req.public_keys
        ])
        # If the subdomain already exists, the response will be a 409
        if response.status_code == 409:
            raise HTTPException(
                status_code = 409,
                detail = (
                    "The given token has already been used or does not "
                    "correspond to a reservation."
                )
            )
        response.raise_for_status()
    return PublicKeyAssociation(
        subdomain = subdomain,
        # Return the non-URL-safe fingerprints so they can be compared with the output of OpenSSH
        fingerprints = [fingerprint(pubkey) for pubkey in req.public_keys]
    )
