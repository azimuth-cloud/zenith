#!/usr/bin/env python3

"""
This script publishes the Helm charts from the repository.

For each chart, it sets the "version" and "appVersion" before packaging it. It then
generates a Helm repository index and commits the charts and the index to the
specified branch.

The version is derived from a combination of the latest Git tag and the current SHA.
It assumes that the tags are SemVer compliant, i.e. are of the form
`<major>.<minor>.<patch>-<prerelease>`.

The appVersion is derived from the current SHA, as produced when using
`tags: type=sha,prefix=` with `docker/metadata-action`.

This means that referencing the chart at a particular version automatically picks up
the matching image for that version.
"""

import base64
import contextlib
import pathlib
import os
import re
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


#: Regex that attempts to match a SemVer version
#: It allows the tag to maybe start with a "v"
SEMVER_REGEX = r"^v?(?P<major>[0-9]+).(?P<minor>[0-9]+).(?P<patch>[0-9]+)(-(?P<prerelease>[a-zA-Z0-9.-]+))?$"


def get_version():
    """
    Returns a (version, app_version) tuple where version is a SemVer-compliant version based on
    Git information for the current working directory and app_version is the short-sha as used
    to tag the operator image.
    
    The version is based on the distance from the last tag and includes the name of the branch that the
    commit is on. It is is constructed such that the versions for a particular branch will order correctly.
    """
    # The app version is always the short SHA
    app_version = cmd(["git", "rev-parse", "--short", "HEAD"])
    # Assembling the version is more complicated
    try:
        # Start by trying to find the most recent tag
        last_tag = cmd(["git", "describe", "--tags", "--abbrev=0"])
    except subprocess.CalledProcessError:
        # If there are no tags, then set the parts in such a way that when we increment the patch version we get 0.1.0
        major_vn = 0
        minor_vn = 1
        patch_vn = -1
        prerelease_vn = None
        # Since there is no tag, just count the number of commits in the branch
        commits = int(cmd(["git", "rev-list", "--count", "HEAD"]))
    else:
        # If we found a tag, split into major/minor/patch/prerelease
        tag_bits = re.search(SEMVER_REGEX, last_tag)
        if tag_bits is None:
            raise RuntimeError(f'Tag is not a valid SemVer version - {last_tag}')
        major_vn = int(tag_bits.group('major'))
        minor_vn = int(tag_bits.group('minor'))
        patch_vn = int(tag_bits.group('patch'))
        prerelease_vn = tag_bits.group('prerelease')
        # Get the number of commits since the last tag
        commits = int(cmd(["git", "rev-list", "--count", f"{last_tag}..HEAD"]))

    if commits > 0:
        # If there are commits since the last tag and no existing prerelease part, increment the patch version
        if not prerelease_vn:
            patch_vn += 1
        # Add information to the prerelease part about the branch and number of commits
        # Get the name of the current branch
        branch_name = cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"]).lower()
        # Sanitise the branch name so it only has characters valid for a prerelease version
        branch_name = re.sub("[^a-zA-Z0-9-]+", "", branch_name).lower()
        prerelease_vn = '.'.join([prerelease_vn or "dev.0", branch_name, str(commits)])

    # Build the SemVer version from the parts
    version = f"{major_vn}.{minor_vn}.{patch_vn}"
    if prerelease_vn:
        version += f"-{prerelease_vn}"

    return version, app_version


def setup_publish_branch(branch, publish_directory):
    """
    Clones the specified branch into the specified directory.
    """
    server_url = os.environ['GITHUB_SERVER_URL']
    repository = os.environ['GITHUB_REPOSITORY']
    remote = f"{server_url}/{repository}.git"
    print(f"[INFO] Cloning {remote}@{branch} into {publish_directory}")
    # Try to clone the branch
    # If it fails, create a new empty git repo with the same remote
    try:
        cmd([
            'git',
            'clone',
            '--depth=1',
            '--single-branch',
            '--branch',
            branch,
            remote,
            publish_directory
        ])
    except subprocess.CalledProcessError:
        with working_directory(publish_directory):
            cmd(['git', 'init'])
            cmd(['git', 'remote', 'add', 'origin', remote])
            cmd(['git', 'checkout', '--orphan', branch])
    username = os.environ['GITHUB_ACTOR']
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
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    # Get the versions to use for the deployed charts
    version, app_version = get_version()
    # Get the chart directories for the Helm charts in the repository
    chart_directories = [
        chart_file.parent
        for chart_file in repo_root.glob("**/Chart.yaml")
    ]

    # Publish the charts and re-generate the repository index
    publish_branch = os.environ.get('PUBLISH_BRANCH', 'gh-pages')
    print(f"[INFO] Chart(s) will be published to branch '{publish_branch}'")
    print(f"[INFO] Chart(s) will be published with version '{version}'")
    with tempfile.TemporaryDirectory() as publish_directory:
        setup_publish_branch(publish_branch, publish_directory)
        for chart_directory in chart_directories:
            print(f"[INFO] Packaging chart in {chart_directory}")
            cmd([
                "helm",
                "package",
                "--dependency-update",
                "--version",
                version,
                "--app-version",
                app_version,
                "--destination",
                publish_directory,
                chart_directory
            ])
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
