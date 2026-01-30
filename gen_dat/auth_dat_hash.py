#!/usr/bin/env python3
"""
PS4 auth.dat HMAC-MD5 hash generation/verification

auth.dat structure (1200 bytes / 0x4B0):
  0x000: version (4 bytes, must be 1)
  0x044: access token (64 bytes)
  0x488: flag (4 bytes, must be 1)
  0x48C: unknown (4 bytes)
  0x490: HMAC-MD5 hash (32 ASCII hex chars)

Hash is computed over first 1160 bytes (0x488) using HMAC-MD5.

Key from SceShellCore (FD82F0):
  auth_datkeymaybe dq 5E59CC6CA92F6328h, 4584A177CD201F20h

In little-endian bytes: 00000000000000000000000000000000
"""

import hmac
import hashlib
import sys

AUTH_DAT_KEY = bytes.fromhex('00000000000000000000000000000000')
AUTH_DAT_SIZE = 1200
AUTH_DAT_HASH_OFFSET = 0x490
AUTH_DAT_DATA_SIZE = 1160  # 0x488


def compute_hash(data: bytes) -> str:
    """Compute HMAC-MD5 hash for auth.dat data (first 1160 bytes)"""
    h = hmac.new(AUTH_DAT_KEY, data[:AUTH_DAT_DATA_SIZE], hashlib.md5)
    return h.hexdigest().upper()


def verify_auth_dat(filepath: str) -> bool:
    """Verify auth.dat file has valid hash"""
    with open(filepath, 'rb') as f:
        data = f.read()

    if len(data) != AUTH_DAT_SIZE:
        print(f"Invalid size: {len(data)} (expected {AUTH_DAT_SIZE})")
        return False

    stored_hash = data[AUTH_DAT_HASH_OFFSET:AUTH_DAT_HASH_OFFSET+32].decode('ascii')
    computed_hash = compute_hash(data)

    print(f"Stored hash:   {stored_hash}")
    print(f"Computed hash: {computed_hash}")
    print(f"Valid: {stored_hash == computed_hash}")

    return stored_hash == computed_hash


def generate_auth_dat(access_token: bytes = None) -> bytes:
    """Generate a valid auth.dat file"""
    buf = bytearray(AUTH_DAT_SIZE)

    # Version
    buf[0] = 0x01

    # Access token at 0x44 (64 bytes)
    if access_token:
        token = access_token[:64].ljust(64, b'\x00')
    else:
        # Fake token
        token = b'A' * 64
    buf[0x44:0x44+64] = token

    # Flag at 0x488
    buf[0x488] = 0x01

    # Compute and write hash at 0x490
    hash_hex = compute_hash(bytes(buf))
    buf[AUTH_DAT_HASH_OFFSET:AUTH_DAT_HASH_OFFSET+32] = hash_hex.encode('ascii')

    return bytes(buf)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} verify <auth.dat>  - Verify existing file")
        print(f"  {sys.argv[0]} generate <output>  - Generate new file")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'verify' and len(sys.argv) >= 3:
        verify_auth_dat(sys.argv[2])
    elif cmd == 'generate' and len(sys.argv) >= 3:
        data = generate_auth_dat()
        with open(sys.argv[2], 'wb') as f:
            f.write(data)
        print(f"Generated {sys.argv[2]}")
        verify_auth_dat(sys.argv[2])
    else:
        print("Invalid command")
        sys.exit(1)
