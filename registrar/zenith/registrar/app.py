import binascii
import base64
import contextlib
import hashlib
import hmac
import secrets
import string
import typing as t

from fastapi import FastAPI, Request, HTTPException

from . import backends
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


# The backend to use
backend = backends.load(settings)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    await backend.startup()
    try:
        yield
    finally:
        await backend.shutdown()


# The FastAPI application
app = FastAPI(lifespan = lifespan)


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
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()


def fingerprint_bytes(ssh_pk: str) -> bytes:
    """
    Returns the raw bytes for the fingerprint of an SSH public key.
    """
    data = binascii.a2b_base64(ssh_pk.split()[1])
    return hashlib.sha256(data).digest()


def fingerprint(ssh_pk: str) -> str:
    """
    Returns the fingerprint for an SSH public key.
    """
    digest = fingerprint_bytes(ssh_pk)
    return base64.b64encode(digest).decode().rstrip("=")


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

    If an SSH public key is given, it is associated with the subdomain and the
    fingerprint is returned. No token is returned in this case.

    If no SSH public key is given, a single-use token is returned that can be used
    to associate a public key with the subdomain.
    """
    if not req:
        req = ReservationRequest()
    # Attempt to reserve a subdomain
    # If we are generating a subdomain, we have a retry in case of a collision
    remaining_attempts = settings.generate_domain_max_attempts
    while remaining_attempts > 0:
        remaining_attempts = remaining_attempts - 1
        # Work out the subdomain that we will attempt to use
        subdomain = req.subdomain if req.subdomain is not None else generate_random_subdomain()
        # Try to reserve the subdomain
        try:
            await backend.reserve_subdomain(subdomain)
        except backends.SubdomainAlreadyReserved:
            # How we react to this depends on whether the request specified a subdomain
            # or whether we generated one
            if req.subdomain is not None:
                raise HTTPException(
                    status_code = 409,
                    detail = "The requested subdomain has already been reserved."
                )
            else:
                continue
        else:
            break
    else:
        # No subdomain allocated after maximum number of attempts
        raise HTTPException(
            status_code = 409,
            detail = "Unable to allocate a subdomain after {} attempts.".format(
                settings.generate_domain_max_attempts
            )
        )
    # If a public key was given, register it with the subdomain we reserved
    if req.public_key:
        try:
            await backend.init_subdomain(subdomain, fingerprint_bytes(req.public_key))
        except backends.SubdomainAlreadyInitialised:
            raise HTTPException(
                status_code = 409,
                detail = "Unable to associate public key."
            )
        except backends.PublicKeyAlreadyAssociated:
            raise HTTPException(
                status_code = 409,
                detail = "Public key is already associated with another subdomain."
            )
    # The FQDN is the requests subdomain combined with the configured base domain
    if settings.subdomain_as_path_prefix:
        fqdn = f"{settings.base_domain}/{subdomain}"
    else:
        fqdn = f"{subdomain}.{settings.base_domain}"
    if req.public_key:
        # When the request contained a public key, return the fingerprint
        return Reservation(
            subdomain = subdomain,
            fqdn = fqdn,
            # Return a fingerprint that can be compared with the output of OpenSSH
            fingerprint = fingerprint(req.public_key)
        )
    else:
        # If no key was given, return a token that can be used to associate a key
        signature = generate_signature(subdomain)
        token = base64.urlsafe_b64encode(f"{subdomain}.{signature}".encode()).decode()
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
    try:
        subdomain = await backend.subdomain_for_public_key(fingerprint_bytes(req.public_key))
    except backends.PublicKeyNotAssociated:
        raise HTTPException(
            status_code = 404,
            detail = "The given SSH public key is not known."
        )
    except backends.PublicKeyHasMultipleAssociations:
        raise HTTPException(
            status_code = 409,
            detail = "The given SSH public key is associated with multiple subdomains."
        )
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
async def associate_public_key(req: PublicKeyAssociationRequest):
    """
    Associate a public key with the subdomain linked to the given token.
    """
    # Extract the token data and signature from the given token
    token_bytes = req.token.encode()
    try:
        decoded_token = base64.urlsafe_b64decode(token_bytes).decode()
        subdomain, signature = decoded_token.rsplit(".", maxsplit = 1)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code = 400, detail = "The given token is invalid.")

    # NOTE(mkjpryor)
    #
    # There are two types of token that we might receive:
    #
    #   1. New-style tokens consisting of a subdomain and a SHA256 signature
    #   2. Old-style tokens consisting of a subdomain, a modify index and a SHA1 signature
    #
    # We only want to accept new-style tokens, as continuing to accept old-style tokens
    # would mean we are reducing our security to SHA1 (i.e. if you want to forge a token,
    # just use an old-style token).
    #
    # However, for backwards compatibility we still want to accept old-style tokens as a
    # valid input, but always reject the request. We use the same error message as other
    # cases where the token is valid but unproceedable, as this allows clients to behave
    # correctly.
    #
    # Old-style tokens will contain a dot in the token data
    if "." in subdomain:
        raise HTTPException(
            status_code = 409,
            detail = (
                "The given token has already been used or does not "
                "correspond to a reservation."
            )
        )

    # For new-style tokens, validate the signature and continue from there
    if not hmac.compare_digest(generate_signature(subdomain), signature):
        raise HTTPException(status_code = 400, detail = "The given token is invalid.")
    # Initialise the subdomain with the public keys
    try:
        await backend.init_subdomain(subdomain, fingerprint_bytes(req.public_key))
    # SubdomainNotReserved should be impossible without knowing the signing key, since
    # the only way to get a token is using the reserve endpoint
    except (backends.SubdomainNotReserved, backends.SubdomainAlreadyInitialised):
        raise HTTPException(
            status_code = 409,
            detail = (
                "The given token has already been used or does not "
                "correspond to a reservation."
            )
        )
    except backends.PublicKeyAlreadyAssociated:
        raise HTTPException(
            status_code = 409,
            detail = "Public key is already associated with another subdomain."
        )
    return PublicKeyAssociation(
        subdomain = subdomain,
        # Return a fingerprint that can be compared with the output of OpenSSH
        fingerprint = fingerprint(req.public_key)
    )
