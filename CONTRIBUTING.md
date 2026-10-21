# Contributing

We welcome contributions and suggestions for improvements to this code base.
Please check for relevant issues and PRs before opening a new one of your own.

## Making a contribution

### Running tests

The Python components are tested with [pytest](https://docs.pytest.org), run via
[tox](https://tox.wiki) and [uv](https://docs.astral.sh/uv/). From the repo root:

```
uv run tox                    # everything CI runs, including a coverage report
uv run tox -m test            # unit tests for every component
uv run tox -e test-operator   # unit tests for one component
uv run tox -e test-operator -- -k templates   # pass arguments to pytest
uv run tox -e lint            # ruff and codespell
uv run tox -m mypy            # type checking (see [tool.mypy] in pyproject.toml)
uv run tox -e autofix         # apply ruff and codespell fixes
```

Tests live in each component's `tests/` directory. They must not need a real
cluster, credentials or network access, so mock clients at the boundary (see
`operator/tests/` for examples). Please add tests alongside your changes.

### Helm template snapshots

The CI in this repository uses the Helm
[unittest](https://github.com/helm-unittest/helm-unittest) plugin's
snapshotting functionality to check PRs for changes to the templated manifests.
Therefore, if your PR makes changes to the manifest templates or values, you
will need to update the saved snapshots to allow your changes to pass the
automated tests. The easiest way to do this is to run the helm unittest command
inside a docker container from the repo root.

```
CHART=/path/to/chart
helm dependency update $CHART
docker run -i --rm -v $(pwd):/apps helmunittest/helm-unittest $CHART -u
```

where the `-u` option is used to update the existing snapshots.
