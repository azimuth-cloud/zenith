import enum
import typing as t

from pydantic import Field, conbytes, conint, conset, constr

from configomatic import Configuration


@enum.unique
class SSHPublicKeyType(str, enum.Enum):
    """
    Enumeration of the possible SSH public key types.
    """
    DSA      = "ssh-dss"
    RSA      = "ssh-rsa"
    ECDSA256 = "ecdsa-sha2-nistp256"
    ECDSA384 = "ecdsa-sha2-nistp384"
    ECDSA521 = "ecdsa-sha2-nistp521"
    ED25519  = "ssh-ed25519"


class RegistrarConfig(Configuration):
    """
    Configuration model for the zenith-registrar package.
    """
    class Config:
        default_path = "/etc/zenith/registrar.yaml"
        path_env_var = "ZENITH_REGISTRAR_CONFIG"
        env_prefix = "ZENITH_REGISTRAR"

    #: The key that is used to sign the subdomain tokens
    subdomain_token_signing_key: conbytes(strip_whitespace = True, min_length = 32)

    #: The base domain that Zenith services are proxied under
    base_domain: constr(min_length = 1)
    #: A list of subdomains that are reserved and cannot be used for Zenith services
    reserved_subdomains: t.List[str] = Field(default_factory = list)

    #: The set of allowed SSH key types
    ssh_allowed_key_types: conset(SSHPublicKeyType, min_items = 1) = Field(
        default_factory = lambda: {
            # By default, DSA keys are not permitted
            # SSHPublicKeyType.DSA,
            # RSA keys are permitted, subject to ssh_rsa_min_bits
            SSHPublicKeyType.RSA,
            # All three sizes of ECDSA are permitted
            SSHPublicKeyType.ECDSA256,
            SSHPublicKeyType.ECDSA384,
            SSHPublicKeyType.ECDSA521,
            # ED25519 is permitted
            SSHPublicKeyType.ED25519,
        }
    )
    #: The minimum size for RSA keys (by default, 1024 bit keys are not allowed)
    ssh_rsa_min_bits: conint(ge = 1024) = 2048

    #: The address of the Consul server
    consul_address: str = "127.0.0.1"
    #: The port of the Consul server
    consul_port: int = 8500
    #: The prefix to use for Consul keys
    consul_key_prefix: str = "zenith-registrar"

    @property
    def consul_url(self):
        """
        The URL to use to access Consul.
        """
        return f"http://{self.consul_address}:{self.consul_port}"


settings = RegistrarConfig()
