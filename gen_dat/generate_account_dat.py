#!/usr/bin/env python3
"""
Generate account.dat with valid HMAC-MD5 hash

account.dat structure (224 bytes / 0xE0):
  0x00: version (4 bytes, must be 1)
  0x08: account_id (8 bytes)
  0x10: 64-char hash/token (64 bytes)
  0x50: online_id (16 bytes + null)
  0x61: region (8 bytes, e.g. "b2us", "a8krps4")
  0x6A: flag byte (1)
  0x72: country (2 bytes, e.g. "us", "kr")
  0x80: language (2 bytes, e.g. "en", "ko")
  0x88: locale (8 bytes, e.g. "en-US", "ko-KR")
  0xB8: flag (4 bytes, must be 1)
  0xBC: unknown (4 bytes)
  0xC0: HMAC-MD5 hash (32 ASCII hex chars)

Hash is computed over first 184 bytes (0xB8) using HMAC-MD5.
Key: 00000000000000000000000000000000 (same as auth.dat)
"""

import hmac
import hashlib
import struct
import sys

ACCOUNT_DAT_KEY = bytes.fromhex('00000000000000000000000000000000')
ACCOUNT_DAT_SIZE = 224  # 0xE0
ACCOUNT_DAT_HASH_OFFSET = 0xC0  # Hash is at 0xC0, not 0xBC
ACCOUNT_DAT_DATA_SIZE = 184  # 0xB8


def generate_account_dat(
    online_id: str = "FakeUser",
    account_id: int = 0x02E9C41757EDA15A,  # Example from real file
    region: str = "b2us",
    country: str = "us",
    language: str = "en",
    locale: str = "en-US"
) -> bytes:
    """Generate account.dat with valid HMAC-MD5 hash"""
    buf = bytearray(ACCOUNT_DAT_SIZE)

    # Version at 0x00 (must be 1)
    struct.pack_into('<I', buf, 0x00, 1)

    # Account ID at 0x08 (8 bytes)
    struct.pack_into('<Q', buf, 0x08, account_id)

    # 64-char filler hash/token at 0x10
    filler_hash = "0" * 64
    buf[0x10:0x10+64] = filler_hash.encode('ascii')

    # Online ID at 0x50 (16 bytes + null terminator at 0x61)
    online_id_bytes = online_id.encode('ascii')[:16].ljust(16, b'\x00')
    buf[0x50:0x50+16] = online_id_bytes
    buf[0x60] = 0x00  # null terminator

    # Region at 0x61 (e.g. "b2us", "a8krps4")
    region_bytes = region.encode('ascii')[:8].ljust(8, b'\x00')
    buf[0x61:0x61+8] = region_bytes

    # Flag at 0x6A
    buf[0x6A] = 0x01

    # Country at 0x72 (2 bytes, e.g. "us", "kr")
    country_bytes = country.encode('ascii')[:2].ljust(2, b'\x00')
    buf[0x72:0x72+2] = country_bytes

    # Language at 0x80 (2 bytes, e.g. "en", "ko")
    language_bytes = language.encode('ascii')[:2].ljust(2, b'\x00')
    buf[0x80:0x80+2] = language_bytes

    # Locale at 0x88 (e.g. "en-US", "ko-KR")
    locale_bytes = locale.encode('ascii')[:8].ljust(8, b'\x00')
    buf[0x88:0x88+8] = locale_bytes

    # Flag at 0xB8 (must be 1)
    struct.pack_into('<I', buf, 0xB8, 1)

    # Compute HMAC-MD5 over first 184 bytes (0xB8)
    h = hmac.new(ACCOUNT_DAT_KEY, bytes(buf[:ACCOUNT_DAT_DATA_SIZE]), hashlib.md5)
    hash_hex = h.hexdigest().upper()

    # Write hash at 0xBC (32 ASCII hex chars)
    buf[ACCOUNT_DAT_HASH_OFFSET:ACCOUNT_DAT_HASH_OFFSET+32] = hash_hex.encode('ascii')

    return bytes(buf)


def verify_account_dat(filepath: str) -> bool:
    """Verify account.dat file has valid hash"""
    with open(filepath, 'rb') as f:
        data = f.read()

    if len(data) != ACCOUNT_DAT_SIZE:
        print(f"Invalid size: {len(data)} (expected {ACCOUNT_DAT_SIZE})")
        return False

    stored_hash = data[ACCOUNT_DAT_HASH_OFFSET:ACCOUNT_DAT_HASH_OFFSET+32].decode('ascii')
    h = hmac.new(ACCOUNT_DAT_KEY, data[:ACCOUNT_DAT_DATA_SIZE], hashlib.md5)
    computed_hash = h.hexdigest().upper()

    print(f"Stored hash:   {stored_hash}")
    print(f"Computed hash: {computed_hash}")
    print(f"Valid: {stored_hash == computed_hash}")

    # Parse and display structure
    version = struct.unpack_from('<I', data, 0x00)[0]
    account_id = struct.unpack_from('<Q', data, 0x08)[0]
    online_id = data[0x50:0x60].rstrip(b'\x00').decode('ascii', errors='replace')
    region = data[0x61:0x69].rstrip(b'\x00').decode('ascii', errors='replace')
    country = data[0x72:0x74].rstrip(b'\x00').decode('ascii', errors='replace')
    language = data[0x80:0x82].rstrip(b'\x00').decode('ascii', errors='replace')
    locale = data[0x88:0x90].rstrip(b'\x00').decode('ascii', errors='replace')

    print(f"\nStructure:")
    print(f"  Version:    {version}")
    print(f"  Account ID: 0x{account_id:016X}")
    print(f"  Online ID:  {online_id}")
    print(f"  Region:     {region}")
    print(f"  Country:    {country}")
    print(f"  Language:   {language}")
    print(f"  Locale:     {locale}")

    return stored_hash == computed_hash


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} generate <output> [online_id]  - Generate new file")
        print(f"  {sys.argv[0]} verify <account.dat>           - Verify existing file")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'generate' and len(sys.argv) >= 3:
        output = sys.argv[2]
        online_id = sys.argv[3] if len(sys.argv) > 3 else "FakeUser"

        data = generate_account_dat(online_id=online_id)

        with open(output, 'wb') as f:
            f.write(data)

        print(f"Generated {output} ({len(data)} bytes)")
        verify_account_dat(output)

    elif cmd == 'verify' and len(sys.argv) >= 3:
        verify_account_dat(sys.argv[2])

    else:
        print("Invalid command")
        sys.exit(1)
