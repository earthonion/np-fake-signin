#!/usr/bin/env python3
"""
Patch all NP dat files from templates with new username/online_id
Recalculates HMAC-MD5 hashes where needed.

Files handled:
- config.dat: User configuration (no HMAC)
- account.dat: Account info with online_id (has HMAC)
- token.dat: Token data (has HMAC)
- auth.dat: Auth session data (has HMAC)

Structure:
- account.dat (224 bytes): data[0x00-0xB7] + ver[0xB8-0xBB] + unk[0xBC-0xBF] + hash[0xC0-0xDF]
- token.dat (368 bytes):   data[0x00-0x147] + ver[0x148-0x14B] + unk[0x14C-0x14F] + hash[0x150-0x16F]
- auth.dat (1200 bytes):   data[0x00-0x487] + ver[0x488-0x48B] + unk[0x48C-0x48F] + hash[0x490-0x4AF]
"""

import struct
import sys
import os
import hmac
import hashlib
import random

# HMAC-MD5 key for dat files - replace zeroes with key ;)
HMAC_KEY = bytes.fromhex("00000000000000000000000000000000")


def calc_hmac_md5(data: bytes) -> str:
    """Calculate HMAC-MD5 and return uppercase hex string"""
    h = hmac.new(HMAC_KEY, data, hashlib.md5)
    return h.hexdigest().upper()


def patch_string(data: bytearray, offset: int, value: str, max_len: int):
    """Patch a null-terminated string at offset"""
    value_bytes = value.encode('ascii')[:max_len-1]
    data[offset:offset+max_len] = b'\x00' * max_len
    data[offset:offset+len(value_bytes)] = value_bytes


def patch_config_dat(template_path: str, output_path: str, username: str,
                     online_id: str = "", email: str = "VUwUE@dryenyen.com",
                     account_id: bytes = None):
    """Patch config.dat - no HMAC needed"""
    with open(template_path, 'rb') as f:
        data = bytearray(f.read())

    if not online_id:
        online_id = username

    # Get country from template
    country = data[0x1BE:0x1C0].rstrip(b'\x00').decode('ascii', errors='replace')
    if not country:
        country = 'us'

    # Patch fields
    patch_string(data, 0x04, username, 17)      # username
    patch_string(data, 0x108, email, 65)        # email
    patch_string(data, 0x1AD, online_id, 17)    # online_id

    # Account ID at 0x100 (8 bytes)
    if account_id:
        data[0x100:0x108] = account_id

    # np_email
    np_email = f"{online_id}@a8.{country}.np.playstation.net"
    patch_string(data, 0x1100, np_email, 65)

    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"  config.dat: username={username}, online_id={online_id}")
    return data


def patch_account_dat(template_path: str, output_path: str, online_id: str,
                      account_id: bytes = None):
    """
    Patch account.dat with online_id and recalculate HMAC

    Structure (224 bytes):
    - 0x00-0x0F: Header + Account ID
    - 0x10-0x4F: 64-char hex hash
    - 0x50: null separator
    - 0x51-0x5F: Online ID (15 bytes)
    - 0x60-0xB7: Other fields (np_env at 0x65, country at 0x75, etc.)
    - 0xB8-0xBB: Version marker (01 00 00 00)
    - 0xBC-0xDF: 36-char HMAC hash
    """
    with open(template_path, 'rb') as f:
        data = bytearray(f.read())

    # Account ID at 0x08 (8 bytes)
    if account_id:
        data[0x08:0x10] = account_id

    # Patch online_id at 0x51 (after null at 0x50)
    patch_string(data, 0x51, online_id, 15)

    # Calculate HMAC over data before version marker (0x00-0xB7 = 184 bytes)
    hmac_data = bytes(data[0x00:0xB8])
    hmac_hex = calc_hmac_md5(hmac_data)

    # Write version marker at 0xB8
    data[0xB8:0xBC] = b'\x01\x00\x00\x00'

    # 0xBC-0xBF: unknown 4 bytes (leave as-is from template)

    # Write 32-char HMAC hash at 0xC0
    data[0xC0:0xE0] = hmac_hex.encode('ascii')

    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"  account.dat: online_id={online_id}, hmac={hmac_hex[:16]}...")
    return data


def patch_token_dat(template_path: str, output_path: str):
    """
    Patch token.dat - recalculate HMAC

    Structure (368 bytes):
    - 0x00-0x147: Data (328 bytes)
    - 0x148-0x14B: Version marker (01 00 00 00)
    - 0x14C-0x16F: 36-char HMAC hash
    """
    with open(template_path, 'rb') as f:
        data = bytearray(f.read())

    # Calculate HMAC over data before version marker (0x00-0x147 = 328 bytes)
    hmac_data = bytes(data[0x00:0x148])
    hmac_hex = calc_hmac_md5(hmac_data)

    # Write version marker at 0x148
    data[0x148:0x14C] = b'\x01\x00\x00\x00'

    # 0x14C-0x14F: unknown 4 bytes (leave as-is from template)

    # Write 32-char HMAC hash at 0x150
    data[0x150:0x170] = hmac_hex.encode('ascii')

    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"  token.dat: hmac={hmac_hex[:16]}...")
    return data


def patch_auth_dat(template_path: str, output_path: str):
    """
    Patch auth.dat - recalculate HMAC

    Structure (1200 bytes):
    - 0x00-0x487: Data (1160 bytes)
    - 0x488-0x48B: Version marker (01 00 00 00)
    - 0x48C-0x4AF: 36-char HMAC hash
    """
    with open(template_path, 'rb') as f:
        data = bytearray(f.read())

    # Calculate HMAC over data before version marker (0x00-0x487 = 1160 bytes)
    hmac_data = bytes(data[0x00:0x488])
    hmac_hex = calc_hmac_md5(hmac_data)

    # Write version marker at 0x488
    data[0x488:0x48C] = b'\x01\x00\x00\x00'

    # 0x48C-0x48F: unknown 4 bytes (leave as-is from template)

    # Write 32-char HMAC hash at 0x490
    data[0x490:0x4B0] = hmac_hex.encode('ascii')

    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"  auth.dat: hmac={hmac_hex[:16]}...")
    return data


def patch_all(template_dir: str, output_dir: str, username: str,
              online_id: str = "", email: str = "VUwUE@dryenyen.com"):
    """Patch all dat files from templates"""

    if not online_id:
        online_id = username

    # Generate random 8-byte account ID
    account_id = random.randbytes(8)

    os.makedirs(output_dir, exist_ok=True)

    print(f"Patching dat files...")
    print(f"  Username:   {username}")
    print(f"  Online ID:  {online_id}")
    print(f"  Email:      {email}")
    print(f"  Account ID: {account_id.hex()}")
    print()

    # config.dat
    patch_config_dat(
        os.path.join(template_dir, "config.dat"),
        os.path.join(output_dir, "config.dat"),
        username, online_id, email, account_id
    )

    # account.dat
    patch_account_dat(
        os.path.join(template_dir, "account.dat"),
        os.path.join(output_dir, "account.dat"),
        online_id, account_id
    )

    # token.dat
    patch_token_dat(
        os.path.join(template_dir, "token.dat"),
        os.path.join(output_dir, "token.dat")
    )

    # auth.dat
    patch_auth_dat(
        os.path.join(template_dir, "auth.dat"),
        os.path.join(output_dir, "auth.dat")
    )

    print()
    print(f"Output written to {output_dir}/")


def show_dat_info(filepath: str):
    """Show info about a dat file"""
    with open(filepath, 'rb') as f:
        data = f.read()

    basename = os.path.basename(filepath)
    print(f"{basename}: {len(data)} bytes")

    if basename == "config.dat":
        print(f"  [0x004] username:   '{data[0x04:0x14].rstrip(b'\\x00').decode('ascii', errors='replace')}'")
        print(f"  [0x100] account_id: {data[0x100:0x108].hex()}")
        print(f"  [0x108] email:      '{data[0x108:0x148].rstrip(b'\\x00').decode('ascii', errors='replace')}'")
        print(f"  [0x1AD] online_id:  '{data[0x1AD:0x1BE].rstrip(b'\\x00').decode('ascii', errors='replace')}'")
        print(f"  [0x1F8] signin_flag:{struct.unpack_from('<I', data, 0x1F8)[0]}")
        print(f"  [0x1100] np_email:  '{data[0x1100:0x1140].rstrip(b'\\x00').decode('ascii', errors='replace')}'")

    elif basename == "account.dat":
        print(f"  [0x08] account_id:  {data[0x08:0x10].hex()}")
        print(f"  [0x51] online_id:   '{data[0x51:0x60].rstrip(b'\\x00').decode('ascii', errors='replace')}'")
        print(f"  [0x65] np_env:      '{data[0x65:0x6D].rstrip(b'\\x00').decode('ascii', errors='replace')}'")
        print(f"  [0x75] country:     '{data[0x75:0x78].rstrip(b'\\x00').decode('ascii', errors='replace')}'")
        print(f"  [0xB8] version:     {data[0xB8:0xBC].hex()}")
        print(f"  [0xC0] hash:        '{data[0xC0:0xE0].decode('ascii', errors='replace')}'")

    elif basename == "token.dat":
        print(f"  [0x00] version:     {struct.unpack_from('<I', data, 0x00)[0]}")
        print(f"  [0x148] ver_mark:   {data[0x148:0x14C].hex()}")
        print(f"  [0x150] hash:       '{data[0x150:0x170].decode('ascii', errors='replace')}'")

    elif basename == "auth.dat":
        print(f"  [0x00] version:     {struct.unpack_from('<I', data, 0x00)[0]}")
        print(f"  [0x44] token:       '{data[0x44:0x84].decode('ascii', errors='replace')[:32]}...'")
        print(f"  [0x488] ver_mark:   {data[0x488:0x48C].hex()}")
        print(f"  [0x490] hash:       '{data[0x490:0x4B0].decode('ascii', errors='replace')}'")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} patch <template_dir> <output_dir> <username> [online_id]")
        print(f"  {sys.argv[0]} show <file.dat>")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} patch template output User1")
        print(f"  {sys.argv[0]} patch template output User1 MyOnlineId")
        print(f"  {sys.argv[0]} show output/account.dat")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'patch' and len(sys.argv) >= 5:
        template_dir = sys.argv[2]
        output_dir = sys.argv[3]
        username = sys.argv[4]
        online_id = sys.argv[5] if len(sys.argv) > 5 else ""

        patch_all(template_dir, output_dir, username, online_id)

    elif cmd == 'show' and len(sys.argv) >= 3:
        show_dat_info(sys.argv[2])

    else:
        print("Invalid command or missing arguments")
        sys.exit(1)
