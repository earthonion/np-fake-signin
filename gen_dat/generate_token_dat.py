#!/usr/bin/env python3
"""
Generate token.dat with valid HMAC-MD5 hash

token.dat structure (368 bytes / 0x170):
  0x00: version (4 bytes, must be 3)
  0x04-0x147: token data (324 bytes, mostly unused)
  0x148: flag (4 bytes, must be 1)
  0x14C: unknown (4 bytes)
  0x150: HMAC-MD5 hash (32 ASCII hex chars)

Hash is computed over first 328 bytes (0x148) using HMAC-MD5.
Key: 00000000000000000000000000000000 (same as auth.dat/account.dat)
"""

import hmac
import hashlib
import struct
import sys

TOKEN_DAT_KEY = bytes.fromhex('00000000000000000000000000000000')
TOKEN_DAT_SIZE = 368  # 0x170
TOKEN_DAT_HASH_OFFSET = 0x150
TOKEN_DAT_DATA_SIZE = 328  # 0x148


def generate_token_dat() -> bytes:
    """Generate token.dat with valid HMAC-MD5 hash"""
    buf = bytearray(TOKEN_DAT_SIZE)

    # Version at 0x00 (must be 3)
    struct.pack_into('<I', buf, 0x00, 3)

    # Token data area 0x04-0x147 is left as zeros

    # Flag at 0x148 (must be 1)
    struct.pack_into('<I', buf, 0x148, 1)

    # Unknown at 0x14C left as zeros

    # Compute HMAC-MD5 over first 328 bytes (0x148)
    h = hmac.new(TOKEN_DAT_KEY, bytes(buf[:TOKEN_DAT_DATA_SIZE]), hashlib.md5)
    hash_hex = h.hexdigest().upper()

    # Write hash at 0x150 (32 ASCII hex chars)
    buf[TOKEN_DAT_HASH_OFFSET:TOKEN_DAT_HASH_OFFSET+32] = hash_hex.encode('ascii')

    return bytes(buf)


def verify_token_dat(filepath: str) -> bool:
    """Verify token.dat file has valid hash"""
    with open(filepath, 'rb') as f:
        data = f.read()

    if len(data) != TOKEN_DAT_SIZE:
        print(f"Invalid size: {len(data)} (expected {TOKEN_DAT_SIZE})")
        return False

    stored_hash = data[TOKEN_DAT_HASH_OFFSET:TOKEN_DAT_HASH_OFFSET+32].decode('ascii', errors='replace')
    h = hmac.new(TOKEN_DAT_KEY, data[:TOKEN_DAT_DATA_SIZE], hashlib.md5)
    computed_hash = h.hexdigest().upper()

    print(f"Stored hash:   {stored_hash}")
    print(f"Computed hash: {computed_hash}")
    print(f"Valid: {stored_hash == computed_hash}")

    # Parse and display structure
    version = struct.unpack_from('<I', data, 0x00)[0]
    flag = struct.unpack_from('<I', data, 0x148)[0]

    print(f"\nStructure:")
    print(f"  Version: {version}")
    print(f"  Flag:    {flag}")

    return stored_hash == computed_hash


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} generate <output>      - Generate new file")
        print(f"  {sys.argv[0]} verify <token.dat>     - Verify existing file")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'generate' and len(sys.argv) >= 3:
        output = sys.argv[2]

        data = generate_token_dat()

        with open(output, 'wb') as f:
            f.write(data)

        print(f"Generated {output} ({len(data)} bytes)")
        verify_token_dat(output)

    elif cmd == 'verify' and len(sys.argv) >= 3:
        verify_token_dat(sys.argv[2])

    else:
        print("Invalid command")
        sys.exit(1)
