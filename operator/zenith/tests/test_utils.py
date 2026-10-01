"""
Tests for zenith.operator.utils.
"""

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
        # None never overrides an existing value
        ({"a": 1}, [{"a": None}], {"a": 1}),
        # Later overrides take precedence
        ({"a": 1}, [{"a": 2}, {"a": 3}], {"a": 3}),
        ({"a": [1]}, [{"a": [2]}, {"a": [3]}], {"a": [1, 2, 3]}),
        ({"a": 1}, [], {"a": 1}),
        # A type mismatch is resolved in favour of the override
        ({"a": {"b": 1}}, [{"a": "x"}], {"a": "x"}),
    ],
)
def test_mergeconcat(defaults, overrides, expected):
    """
    Check dict merging, list concatenation, None handling and override precedence.
    """
    assert mergeconcat(defaults, *overrides) == expected


def test_mergeconcat_does_not_mutate_inputs():
    """
    Check that mergeconcat leaves its inputs unmodified.
    """
    defaults = {"a": {"b": [1]}}
    overrides = {"a": {"b": [2]}}
    mergeconcat(defaults, overrides)
    assert defaults == {"a": {"b": [1]}}
    assert overrides == {"a": {"b": [2]}}
