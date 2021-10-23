#!/usr/bin/env python3

"""
This script publishes the Helm charts from the given directory with the
given version and appVersion.
"""

import base64
import contextlib
import pathlib
import os
import subprocess
import tempfile



@contextlib.contextmanager
def working_directory(directory):
    """
    Context manager that runs the wrapped code with the given directory as the
    working directory.

    When the context manager exits, the original working directory is restored.
    """
    previous_cwd = os.getcwd()
    os.chdir(directory)
    try:
        yield
    finally:
        os.chdir(previous_cwd)


def cmd(command):
    """
    Execute the given command and return the output.
    """
    output = subprocess.check_output(command, text = True, stderr = subprocess.DEVNULL)
    return output.strip()


def setup_publish_branch(branch, publish_directory):
    """
    Clones the specified branch into the specified directory.
    """
    server_url = os.environ["GITHUB_SERVER_URL"]
    repository = os.environ["GITHUB_REPOSITORY"]
    remote = f"{server_url}/{repository}.git"
    print(f"[INFO] Cloning {remote}@{branch} into {publish_directory}")
    # Try to clone the branch
    # If it fails, create a new empty git repo with the same remote
    try:
        cmd([
            "git",
            "clone",
            "--depth=1",
            "--single-branch",
            "--branch",
            branch,
            remote,
            publish_directory
        ])
    except subprocess.CalledProcessError:
        with working_directory(publish_directory):
            cmd(["git", "init"])
            cmd(["git", "remote", "add", "origin", remote])
            cmd(["git", "checkout", "--orphan", branch])
    username = os.environ["GITHUB_ACTOR"]
    email = f"{username}@users.noreply.github.com"
    with working_directory(publish_directory):
        print(f"[INFO] Configuring git to use username '{username}'")
        cmd(["git", "config", "user.name", username])
        cmd(["git", "config", "user.email", email])
        print("[INFO] Configuring git to use authentication token")
        # Basic auth credentials should be base64-encoded
        basic_auth = f"x-access-token:{os.environ['GITHUB_TOKEN']}"
        cmd([
            "git",
            "config",
            "http.extraheader",
            f"Authorization: Basic {base64.b64encode(basic_auth.encode()).decode()}"
        ])


def main():
    """
    Entrypoint for the script.
    """
    # Get the directory to publish charts from
    chart_directory = pathlib.Path(os.environ.get("CHART_DIRECTORY") or  ".").resolve()

    # Get the versions to use for the deployed charts
    version = os.environ.get("VERSION")
    app_version = os.environ.get("APP_VERSION")

    # Get the chart directories for the Helm charts under the given directory
    chart_directories = [
        chart_file.parent
        for chart_file in chart_directory.glob("**/Chart.yaml")
    ]

    # Publish the charts and re-generate the repository index
    publish_branch = os.environ.get("PUBLISH_BRANCH") or "gh-pages"
    print(f"[INFO] Chart(s) will be published to branch '{publish_branch}'")
    print(f"[INFO] Chart(s) will be published with version '{version}'")
    print(f"[INFO] Chart(s) will be published with appVersion '{app_version}'")
    with tempfile.TemporaryDirectory() as publish_directory:
        setup_publish_branch(publish_branch, publish_directory)
        for chart_directory in chart_directories:
            print(f"[INFO] Packaging chart in {chart_directory}")
            args = [
                "helm",
                "package",
                "--dependency-update",
                "--destination",
                publish_directory,
                chart_directory
            ]
            if version:
                args.extend(["--version", version])
            if app_version:
                args.extend(["--app-version", app_version])
            cmd(args)
        # Re-index the publish directory
        print("[INFO] Generating Helm repository index file")
        cmd(["helm", "repo", "index", publish_directory])
        with working_directory(publish_directory):
            print("[INFO] Committing changed files")
            cmd(["git", "add", "-A"])
            cmd(["git", "commit", "-m", f"Publishing charts for {version}"])
            print(f"[INFO] Pushing changes to branch '{publish_branch}'")
            cmd(["git", "push", "--set-upstream", "origin", publish_branch])


if __name__ == "__main__":
    main()
