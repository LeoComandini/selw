import wallycore as wally


h2b = wally.hex_to_bytes
b2h = wally.hex_from_bytes


def h2b_rev(h):
    return wally.hex_to_bytes(h)[::-1]


def b2h_rev(b):
    return wally.hex_from_bytes(b[::-1])
