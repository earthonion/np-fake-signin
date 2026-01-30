#!/usr/bin/env python3
"""
Generate auth.dat with filler access token
"""

import hmac
import hashlib
import sys

AUTH_DAT_KEY = bytes.fromhex('00000000000000000000000000000000')
AUTH_DAT_SIZE = 1200  # 0x4B0


def generate_auth_dat(access_token: str = None) -> bytes:
    """Generate auth.dat with valid HMAC-MD5 hash"""
    buf = bytearray(AUTH_DAT_SIZE)

    # Version at 0x00 (must be 1)
    buf[0x00] = 0x01

    # Access token at 0x44 (64 bytes)
    if access_token is None:
        access_token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    token_bytes = access_token.encode('ascii')[:64].ljust(64, b'\x00')
    buf[0x44:0x44+64] = token_bytes

    # Flag at 0x488 (must be 1)
    buf[0x488] = 0x01

    # Compute HMAC-MD5 over first 1160 bytes (0x488)
    h = hmac.new(AUTH_DAT_KEY, bytes(buf[:1160]), hashlib.md5)
    hash_hex = h.hexdigest().upper()

    # Write hash at 0x490 (32 ASCII hex chars)
    buf[0x490:0x490+32] = hash_hex.encode('ascii')

    return bytes(buf)


if __name__ == '__main__':
    output = sys.argv[1] if len(sys.argv) > 1 else 'auth.dat'
    token = sys.argv[2] if len(sys.argv) > 2 else None

    data = generate_auth_dat(token)

    with open(output, 'wb') as f:
        f.write(data)

    print(f"Generated {output} ({len(data)} bytes)")
    print(f"Token: {data[0x44:0x44+64].rstrip(b'\\x00').decode('ascii')}")
    print(f"Hash:  {data[0x490:0x490+32].decode('ascii')}")
