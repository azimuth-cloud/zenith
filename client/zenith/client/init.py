import json
import logging
import subprocess
import sys

import requests


logger = logging.getLogger(__name__)


def ensure_ssh_identity(config):
    """
    Ensure that the specified SSH identity exists and return the public key.
    """
    if config.ssh_identity_path.exists():
        logger.info(f"Using existing SSH identity at {config.ssh_identity_path}")
    else:
        logger.info(f"Generating SSH identity at {config.ssh_identity_path}")
        subprocess.check_call([
            config.ssh_keygen_executable,
            "-t",
            "rsa",
            "-b",
            "2048",
            "-N",
            "",
            "-C",
            "zenith-key",
            "-f",
            config.ssh_identity_path
        ])
    with config.ssh_identity_path.with_suffix(".pub").open() as fh:
        return fh.read().strip()


def run(config):
    """
    Runs the client initialisation.
    """
    ssh_pubkey = ensure_ssh_identity(config)
    logger.info(f"Uploading public key to registrar at {config.registrar_url}")
    data = { "token": config.token, "public_keys": [ssh_pubkey] }
    response = requests.post(
        config.registrar_url + "/associate",
        json = data,
        verify = config.verify_ssl
    )
    if 200 <= response.status_code < 300:
        fingerprint = response.json()["fingerprints"][0]
        logger.info(f"Public key SHA256:{fingerprint} uploaded successfully")
    else:
        try:
            message = response.json()["detail"]
        except json.JSONDecodeError:
            message = f"{response.status_code} {response.reason}"
        logger.error(message.rstrip('.'))
        sys.exit(1)
