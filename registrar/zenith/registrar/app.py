import binascii
import base64
import hashlib
import hmac
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


app = FastAPI()


def generate_signature(message: str) -> str:
    """
    Generates a signature for the given message using the signing key.
    """
    key = settings.subdomain_token_signing_key
    return hmac.new(key, message.encode(), hashlib.sha1).hexdigest()


def fingerprint(ssh_pubkey: str) -> str:
    """
    Returns the fingerprint for an SSH public key.
    """
    return hashlib.sha256(base64.b64decode(ssh_pubkey.split()[1])).hexdigest()


@app.post(
    "/reserve",
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
    Reserve a subdomain and return a single-use URL that can be used to associate public keys.
    """
    if not req:
        req = ReservationRequest()
    signature = generate_signature(req.subdomain)
    # The actual token is the subdomain + the message then base64 encoded
    token = base64.urlsafe_b64encode(f"{req.subdomain}.{signature}".encode()).decode()
    associate_url = request.url_for(associate_public_keys.__name__, token = token)
    return Reservation(subdomain = req.subdomain, associate_url = associate_url)


@app.post(
    "/associate/{token}",
    response_model = PublicKeyAssociation,
    responses = {
        400: {
            "description": "The given token is invalid.",
            "model": Error,
        },
        409: {
            "description": "The given token has already been used.",
            "model": Error,
        },
    }
)
async def associate_public_keys(token: str, req: PublicKeyAssociationRequest):
    """
    Associate one or more public keys with the subdomain linked to the given token.
    """
    # Extract the subdomain and signature from the given token
    token_bytes = token.encode()
    try:
        decoded_token = base64.urlsafe_b64decode(token_bytes).decode()
        subdomain, signature = decoded_token.split(".", maxsplit = 1)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code = 400, detail = "The given token is invalid.")
    # Verify the signature
    if not hmac.compare_digest(generate_signature(subdomain), signature):
        raise HTTPException(status_code = 400, detail = "The given token is invalid.")
    # Check if the subdomain already has keys associated and bail if it has
    async with AsyncClient(base_url = settings.consul_url) as client:
        # Use a transaction to update the subdomain record and pubkey records atomically
        response = await client.put("/v1/txn", json = [
            {
                "KV": {
                    # Use check-and-set (cas) semantics for the subdomain operation
                    # Using an index of zero means that this operation only succeeds if the
                    # subdomain does not exist
                    # Combined with the transaction, that means none of the operations will
                    # succeed if the subdomain already exists 
                    "Verb": "cas",
                    "Index": 0,
                    "Key": f"{settings.consul_key_prefix}/subdomains/{subdomain}",
                    # Any value is fine, just to mark the domain as seen
                    "Value": base64.b64encode(b"1").decode(),
                },
            },
        ] + [
            {
                "KV": {
                    # Use regular set semantics here, as we don't care about splatting existing
                    # pubkey records (it shouldn't happen with a well-behaved client anyway)
                    "Verb": "set",
                    "Key": f"{settings.consul_key_prefix}/pubkeys/{fingerprint(pubkey)}",
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
                detail = "The given token has already been used."
            )
        response.raise_for_status()
    return PublicKeyAssociation(subdomain = subdomain, public_keys = req.public_keys)


@app.post(
    "/verify",
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
        url = f"/v1/kv/{settings.consul_key_prefix}/pubkeys/{fingerprint(req.public_key)}"
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
