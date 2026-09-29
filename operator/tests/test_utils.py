"""Test the deep-merge helper used by the templates."""

from typing import Any

import pytest
from zenith.operator.utils import mergeconcat


@pytest.mark.parametrize(
    ("defaults", "overrides", "expected"),
    [
        ({"a": 1}, [{"b": 2}], {"a": 1, "b": 2}),
        ({"a": 1}, [{"a": 2}], {"a": 2}),
        ({"a": {"b": 1, "c": 2}}, [{"a": {"c": 3}}], {"a": {"b": 1, "c": 3}}),
        ({"a": [1]}, [{"a": [2]}], {"a": [1, 2]}),
        ({"a": (1,)}, [{"a": [2]}], {"a": [1, 2]}),
        ({"a": 1}, [{"a": None}], {"a": 1}),
        ({"a": 1}, [{"a": 2}, {"a": 3}], {"a": 3}),
        ({"a": [1]}, [{"a": [2]}, {"a": [3]}], {"a": [1, 2, 3]}),
        ({"a": 1}, [], {"a": 1}),
        ({"a": {"b": 1}}, [{"a": "x"}], {"a": "x"}),
    ],
    ids=[
        "new-key",
        "override-scalar",
        "nested-dict",
        "concat-list",
        "concat-tuple",
        "none-keeps-default",
        "rightmost-wins",
        "concat-many",
        "no-overrides",
        "type-mismatch-override-wins",
    ],
)
def test_mergeconcat(
    defaults: dict[str, Any], overrides: list[dict[str, Any]], expected: dict[str, Any]
) -> None:
    """
    Check that dicts merge, sequences concatenate and later overrides win.

    The templates use this to layer client settings over operator defaults.
    """
    assert mergeconcat(defaults, *overrides) == expected


def test_mergeconcat_does_not_mutate_inputs() -> None:
    """
    Check that the defaults and overrides are not modified.

    The defaults are shared operator settings, so mutating them leaks between clients.
    """
    defaults = {"a": {"b": [1]}}
    overrides = {"a": {"b": [2]}}
    mergeconcat(defaults, overrides)
    assert defaults == {"a": {"b": [1]}}
    assert overrides == {"a": {"b": [2]}}
