#!/usr/bin/env python3

"""
This script generates a SemVer-compatible version for the current commit using a combination
of the last tag, the distance from that tag and the name of the branch that the commit is on.

The version is constructed such that the versions for a particular branch will order correctly.

It is assumed that tags are SemVer compliant, i.e. `<major>.<minor>.<patch>-<prerelease>`.

It also returns a short-sha as a secondary output.
"""

import re
import subprocess


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
    Returns a (version, short_sha) tuple where version is a SemVer-compliant version based on
    Git information for the current working directory.
    """
    # Getting the short SHA is easy
    short_sha = cmd(["git", "rev-parse", "--short", "HEAD"])
    # Deriving the semver version is more tricky
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

    return version, short_sha


def main():
    """
    Entrypoint for the script.
    """
    version, short_sha = get_version()
    print(f"::set-output name=version::{version}")
    print(f"::set-output name=short-sha::{short_sha}")


if __name__ == "__main__":
    main()
