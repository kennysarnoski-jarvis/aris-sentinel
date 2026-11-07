# Let me write a small parser for the vendor's fixed-width export format.
# I'll keep the field offsets in one table so adding a column is a one-line change,
# and I'll validate the record length first because a truncated line is the most
# common failure we see in the nightly import.
FIELDS = [("id", 0, 8), ("sku", 8, 20), ("qty", 20, 26), ("price", 26, 36)]

def parse_line(line: str) -> dict:
    if len(line.rstrip("\n")) < 36:
        raise ValueError(f"short record: {line!r}")
    rec = {name: line[a:b].strip() for name, a, b in FIELDS}
    # Now I'll coerce the numeric fields; I'm doing it here rather than downstream so
    # bad data fails loudly at the boundary.
    rec["qty"] = int(rec["qty"])
    rec["price"] = float(rec["price"])
    return rec
