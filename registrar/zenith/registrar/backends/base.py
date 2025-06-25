import base64

from .. import config  # noqa: TID252


class BackendError(Exception):
    """
    Base class for backend errors.
    """


class SubdomainAlreadyReserved(BackendError):  # noqa: N818
    """
    Raised when an attempt is made to reserve a subdomain that is already reserved.
    """

    def __init__(self, subdomain: str):
        super().__init__(f"subdomain '{subdomain}' is already reserved")


class SubdomainNotReserved(BackendError):  # noqa: N818
    """
    Raised when an attempt is made to initialise a subdomain that is not reserved.
    """

    def __init__(self, subdomain: str):
        super().__init__(f"subdomain '{subdomain}' has not been reserved")


class SubdomainAlreadyInitialised(BackendError):  # noqa: N818
    """
    Raised when an attempt is made to initialise a subdomain that is already
    initialised.
    """

    def __init__(self, subdomain: str):
        super().__init__(f"subdomain '{subdomain}' is already initialised")


class PublicKeyAlreadyAssociated(BackendError):  # noqa: N818
    """
    Raised when an attempt is made to initialise a subdomain with a public key that is
    already associated with another subdomain.
    """

    def __init__(self, fingerprint: bytes):
        fingerprint_str = base64.b64encode(fingerprint).decode().rstrip("=")
        super().__init__(
            f"public key '{fingerprint_str}' is already associated with a subdomain"
        )


class PublicKeyNotAssociated(BackendError):  # noqa: N818
    """
    Raised during verify when a public key is not associated with a subdomain.
    """

    def __init__(self, fingerprint: bytes):
        fingerprint_str = base64.b64encode(fingerprint).decode().rstrip("=")
        super().__init__(
            f"public key '{fingerprint_str}' is not associated with a subdomain"
        )


class PublicKeyHasMultipleAssociations(BackendError):  # noqa: N818
    """
    Raised during verify when a public key is associated with multiple subdomains.
    """

    def __init__(self, fingerprint: bytes):
        fingerprint_str = base64.b64encode(fingerprint).decode().rstrip("=")
        super().__init__(
            f"public key '{fingerprint_str}' is already associated with a subdomain"
        )


class Backend:
    """
    Base class for a registrar backend.
    """

    async def reserve_subdomain(self, subdomain: str):
        """
        Reserve a subdomain for use with an application.

        If the specified subdomain is already reserved, an exception is raised.
        """
        raise NotImplementedError

    async def init_subdomain(self, subdomain: str, fingerprint: bytes):
        """
        Initialise a subdomain with an SSH public key, using the fingerprint.

        If the subdomain is not reserved, is already initialised, or the public key is
        already associated with another subdomain, an exception is raised.
        """
        raise NotImplementedError

    async def subdomain_for_public_key(self, fingerprint: bytes) -> str:
        """
        Returns the subdomain that is associated with the given public key fingerprint.

        If the public key is not associated with a subdomain, or is associated with
        multiple subdomains, an exception is raised.
        """
        raise NotImplementedError

    async def startup(self):
        """
        Perform any startup tasks that are required.
        """

    async def shutdown(self):
        """
        Perform any shutdown tasks that are required.
        """

    async def __aenter__(self):
        await self.startup()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.shutdown()

    @classmethod
    def from_config(cls, config_obj: config.RegistrarConfig) -> "Backend":
        """
        Initialises an instance of the backend from a config object.
        """
        raise NotImplementedError
