#!/usr/bin/env python3
"""
Generate config.dat for PS4 user configuration

config.dat structure (8192 bytes / 0x2000):
  NO HMAC HASH - file is not cryptographically protected

Key fields:
  0x000: userId (4 bytes) - internal flags, often 0x10000000
  0x004: username (17 bytes)
  0x04C: field_5 (4 bytes)
  0x050: field_6 (4 bytes) - often 6
  0x058: field (4 bytes) - often 0x870
  0x100: account_id (8 bytes)
  0x108: email (65 bytes)
  0x177: np_env (17 bytes) - usually "np"
  0x1AD: online_id (17 bytes)
  0x1BE: country (2 bytes) - e.g. "kr", "us"
  0x1C1: language (2 bytes) - e.g. "ko", "en"
  0x1C7: locale (16 bytes) - e.g. "ko-KR", "en-US"
  0x1F4: field (4 bytes)
  0x200: flags section
  0x2EC: config_version (4 bytes)
  0x318: token (varies)

Trophy-related fields in 0x200-0x2E0 range
Additional fields at 0x1100+ for extended data
"""

import struct
import sys


CONFIG_DAT_SIZE = 8192  # 0x2000


def generate_config_dat(
    username: str = "User",
    online_id: str = None,
    account_id: int = 0,
    email: str = "",
    country: str = "us",
    language: str = "en",
    locale: str = "en-US",
    np_env: str = "np",
    np_email: str = "",      # Extended: NP email at 0x1100
    birthday: str = "",       # Extended: birthday at 0x1141 (YYYY-MM-DD)
    token_hash: str = ""      # Extended: token at 0x114C
) -> bytes:
    """Generate config.dat file"""
    buf = bytearray(CONFIG_DAT_SIZE)

    if online_id is None:
        online_id = username

    # userId/flags at 0x00 - typical value
    struct.pack_into('<I', buf, 0x00, 0x10000000)

    # Username at 0x04 (17 bytes max)
    username_bytes = username.encode('ascii')[:16]
    buf[0x04:0x04+len(username_bytes)] = username_bytes

    # Field 5 at 0x4C
    struct.pack_into('<I', buf, 0x4C, 0x3AF)

    # Field 6 at 0x50
    struct.pack_into('<I', buf, 0x50, 6)

    # Field at 0x58
    struct.pack_into('<I', buf, 0x58, 0x870)

    # Some flags in 0x68-0x9C range
    struct.pack_into('<I', buf, 0x70, 0x0C)  # 0x70
    struct.pack_into('<I', buf, 0x74, 0x19)  # 0x74
    struct.pack_into('<I', buf, 0x78, 0x0F)  # 0x78
    struct.pack_into('<I', buf, 0x7C, 0x03)  # 0x7C
    struct.pack_into('<I', buf, 0x80, 0x01)  # 0x80
    struct.pack_into('<I', buf, 0x84, 0x02)  # 0x84
    struct.pack_into('<I', buf, 0x8C, 0x04)  # 0x8C
    struct.pack_into('<I', buf, 0x90, 0x20)  # 0x90
    struct.pack_into('<I', buf, 0x94, 0x01)  # 0x94

    # Account ID at 0x100 (8 bytes)
    struct.pack_into('<Q', buf, 0x100, account_id)

    # Email at 0x108 (65 bytes max)
    if email:
        email_bytes = email.encode('ascii')[:64]
        buf[0x108:0x108+len(email_bytes)] = email_bytes

    # NP environment at 0x177 (17 bytes)
    np_bytes = np_env.encode('ascii')[:16]
    buf[0x177:0x177+len(np_bytes)] = np_bytes

    # Online ID at 0x1AD (17 bytes)
    online_bytes = online_id.encode('ascii')[:16]
    buf[0x1AD:0x1AD+len(online_bytes)] = online_bytes

    # Country at 0x1BE (2 bytes)
    country_bytes = country.encode('ascii')[:2]
    buf[0x1BE:0x1BE+len(country_bytes)] = country_bytes

    # Language at 0x1C1 (2 bytes)
    language_bytes = language.encode('ascii')[:2]
    buf[0x1C1:0x1C1+len(language_bytes)] = language_bytes

    # Locale at 0x1C7 (16 bytes)
    locale_bytes = locale.encode('ascii')[:15]
    buf[0x1C7:0x1C7+len(locale_bytes)] = locale_bytes

    # Field at 0x1F4
    struct.pack_into('<I', buf, 0x1F4, 0x26)
    struct.pack_into('<I', buf, 0x1F8, 0x02)

    # Flags at 0x210, 0x224
    struct.pack_into('<I', buf, 0x210, 0x01)
    struct.pack_into('<I', buf, 0x224, 0x01)

    # Flags at 0x284
    struct.pack_into('<I', buf, 0x284, 0x06)
    struct.pack_into('<I', buf, 0x288, 0x01)
    struct.pack_into('<I', buf, 0x28C, 0x01)
    struct.pack_into('<I', buf, 0x290, 0x0C000001)
    struct.pack_into('<I', buf, 0x294, 0x01)

    # Flags at 0x2C4
    struct.pack_into('<I', buf, 0x2C4, 0x26)
    struct.pack_into('<I', buf, 0x2C8, 0x10)
    struct.pack_into('<I', buf, 0x2CC, 0x04)

    # Flag at 0x304
    struct.pack_into('<I', buf, 0x304, 0x01)

    # Flags at 0x330
    struct.pack_into('<I', buf, 0x330, 0x04)
    struct.pack_into('<I', buf, 0x334, 0x01)

    # Extended fields at 0x1100+
    # NP email at 0x1100 (65 bytes) - e.g. "username@a8.kr.np.playstation.net"
    if np_email:
        np_email_bytes = np_email.encode('ascii')[:64]
        buf[0x1100:0x1100+len(np_email_bytes)] = np_email_bytes
    elif online_id:
        # Auto-generate NP email from online_id if not provided
        auto_np_email = f"{online_id}@a8.{country}.np.playstation.net"
        np_email_bytes = auto_np_email.encode('ascii')[:64]
        buf[0x1100:0x1100+len(np_email_bytes)] = np_email_bytes

    # Birthday at 0x1141 (11 bytes) - format: YYYY-MM-DD
    if birthday:
        birthday_bytes = birthday.encode('ascii')[:10]
        buf[0x1141:0x1141+len(birthday_bytes)] = birthday_bytes

    # Token hash at 0x114C (65 bytes)
    if token_hash:
        token_bytes = token_hash.encode('ascii')[:64]
        buf[0x114C:0x114C+len(token_bytes)] = token_bytes

    return bytes(buf)


def parse_config_dat(filepath: str) -> dict:
    """Parse config.dat file and return field values"""
    with open(filepath, 'rb') as f:
        data = f.read()

    if len(data) != CONFIG_DAT_SIZE:
        print(f"Warning: size {len(data)} != expected {CONFIG_DAT_SIZE}")

    fields = {}

    # Parse known fields
    fields['userId'] = struct.unpack_from('<I', data, 0x00)[0]
    fields['username'] = data[0x04:0x14].rstrip(b'\x00').decode('ascii', errors='replace')
    fields['field_5'] = struct.unpack_from('<I', data, 0x4C)[0]
    fields['field_6'] = struct.unpack_from('<I', data, 0x50)[0]
    fields['account_id'] = struct.unpack_from('<Q', data, 0x100)[0]
    fields['email'] = data[0x108:0x148].rstrip(b'\x00').decode('ascii', errors='replace')
    fields['np_env'] = data[0x177:0x187].rstrip(b'\x00').decode('ascii', errors='replace')
    fields['online_id'] = data[0x1AD:0x1BE].rstrip(b'\x00').decode('ascii', errors='replace')
    fields['country'] = data[0x1BE:0x1C0].rstrip(b'\x00').decode('ascii', errors='replace')
    fields['language'] = data[0x1C1:0x1C3].rstrip(b'\x00').decode('ascii', errors='replace')
    fields['locale'] = data[0x1C7:0x1D7].rstrip(b'\x00').decode('ascii', errors='replace')
    fields['config_version'] = struct.unpack_from('<I', data, 0x2EC)[0]

    return fields


def dump_config_dat(filepath: str):
    """Dump config.dat fields"""
    fields = parse_config_dat(filepath)

    print(f"config.dat: {filepath}")
    print(f"  Size: {CONFIG_DAT_SIZE} bytes (0x{CONFIG_DAT_SIZE:X})")
    print()
    print("Fields:")
    print(f"  userId:         0x{fields['userId']:08X}")
    print(f"  username:       '{fields['username']}'")
    print(f"  field_5:        {fields['field_5']} (0x{fields['field_5']:X})")
    print(f"  field_6:        {fields['field_6']}")
    print(f"  account_id:     0x{fields['account_id']:016X}")
    print(f"  email:          '{fields['email']}'")
    print(f"  np_env:         '{fields['np_env']}'")
    print(f"  online_id:      '{fields['online_id']}'")
    print(f"  country:        '{fields['country']}'")
    print(f"  language:       '{fields['language']}'")
    print(f"  locale:         '{fields['locale']}'")
    print(f"  config_version: {fields['config_version']}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} generate <output> [username] [online_id]")
        print(f"  {sys.argv[0]} dump <config.dat>")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'generate' and len(sys.argv) >= 3:
        output = sys.argv[2]
        username = sys.argv[3] if len(sys.argv) > 3 else "User"
        online_id = sys.argv[4] if len(sys.argv) > 4 else None

        data = generate_config_dat(username=username, online_id=online_id)

        with open(output, 'wb') as f:
            f.write(data)

        print(f"Generated {output} ({len(data)} bytes)")
        dump_config_dat(output)

    elif cmd == 'dump' and len(sys.argv) >= 3:
        dump_config_dat(sys.argv[2])

    else:
        print("Invalid command")
        sys.exit(1)
