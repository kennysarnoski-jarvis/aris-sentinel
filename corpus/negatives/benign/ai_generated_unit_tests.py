# Tests for pricing.apply_discount, generated with assistance and then reviewed.
# I'm covering the three branches explicitly (no discount, percentage, fixed) and one
# edge case per branch, because the last regression here was a negative total that
# nobody had a test for.
import pytest
from pricing import apply_discount

def test_no_discount_returns_total():
    assert apply_discount(100.0, None) == 100.0

def test_percentage_discount():
    assert apply_discount(100.0, {"type": "pct", "value": 15}) == 85.0

def test_fixed_discount_never_goes_negative():
    # Edge case: a fixed discount larger than the total should clamp at zero.
    assert apply_discount(10.0, {"type": "fixed", "value": 25}) == 0.0

def test_unknown_type_raises():
    with pytest.raises(ValueError):
        apply_discount(10.0, {"type": "bogus", "value": 1})
