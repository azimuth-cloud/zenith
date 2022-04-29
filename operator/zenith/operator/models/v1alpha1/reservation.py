import typing as t

from pydantic import Extra, Field, constr

from ..schema import BaseModel, Enum


class ReservationSpec(BaseModel):
    """
    Model for the spec of a reservation.
    """
    credential_secret_name: constr(regex = r"^[a-z0-9-]+$") = Field(
        ...,
        description = (
            "The name of the secret to use for the SSH keypair for the reservation. "
            "If the secret already exists, the existing keypair will be used. "
            "If the secret does not exist, a keypair will be generated and put in the secret."
        )
    )
    credential_secret_public_key_name: constr(regex = r"^[a-zA-Z0-9._-]+$") = Field(
        "ssh-publickey",
        description = "The name of the key in the secret that holds the public key data."
    )
    credential_secret_private_key_name: constr(regex = r"^[a-zA-Z0-9._-]+$") = Field(
        "ssh-privatekey",
        description = "The name of the key in the secret that holds the private key data."
    )


class ReservationPhase(str, Enum):
    """
    Enum of the possible choices for the phase of a reservation.
    """
    PENDING = "Pending"
    READY   = "Ready"
    FAILED  = "Failed"
    UNKNOWN = "Unknown"

 
class ReservationStatus(BaseModel):
    """
    Model for the status of a reservation.
    """
    class Config:
        extra = Extra.allow
    
    phase: ReservationPhase = Field(
        ReservationPhase.UNKNOWN,
        description = "The phase of the reservation."
    )
    subdomain: t.Optional[str] = Field(
        None,
        description = "The subdomain that was allocated for the reservation."
    )
    fqdn: t.Optional[str] = Field(
        None,
        description = "The FQDN at which the Zenith service for the reservation can be reached."
    )
    fingerprint: t.Optional[str] = Field(
        None,
        description = "The fingerprint of the SSH key that was registered."
    )


class Reservation(BaseModel):
    """
    Model for a Zenith reservation.
    """
    spec: ReservationSpec = Field(
        ...,
        description = "The specification for the Zenith reservation."
    )
    status: ReservationStatus = Field(
        default_factory = ReservationStatus,
        description = "The status of the Zenith reservation."
    )
