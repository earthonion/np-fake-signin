#!/usr/bin/env python3
"""
Patch config.dat template with new username/online_id

Uses a legitimate config.dat as template and patches username fields.
This preserves all the complex NP Manager, PS Plus, Parental, etc. fields.
"""

import struct
import sys
import os

CONFIG_DAT_SIZE = 8192  # 0x2000

# Field offsets to patch
OFFSETS = {
    'username':   (0x004, 17),   # username string
    'online_id':  (0x1AD, 17),   # online_id string
    'np_email':   (0x1100, 65),  # NP email string
}


def patch_config_dat(template_path: str, output_path: str, username: str,
                     online_id: str = None, country: str = None,
                     email: str = "VUwUE@dryenyen.com"):
    """Patch config.dat template with new username"""

    # Read template
    with open(template_path, 'rb') as f:
        data = bytearray(f.read())

    if len(data) != CONFIG_DAT_SIZE:
        print(f"Warning: template size {len(data)} != expected {CONFIG_DAT_SIZE}")

    # Use username as online_id if not specified
    if online_id is None:
        online_id = username

    # Get country from template if not specified
    if country is None:
        country = data[0x1BE:0x1C0].rstrip(b'\x00').decode('ascii', errors='replace')
        if not country:
            country = 'us'

    # Patch username at 0x04
    username_bytes = username.encode('ascii')[:16]
    data[0x04:0x04+17] = b'\x00' * 17  # Clear first
    data[0x04:0x04+len(username_bytes)] = username_bytes
    print(f"  Patched username: '{username}'")

    # Patch email at 0x108
    email_bytes = email.encode('ascii')[:64]
    data[0x108:0x108+65] = b'\x00' * 65  # Clear first
    data[0x108:0x108+len(email_bytes)] = email_bytes
    print(f"  Patched email: '{email}'")

    # Patch online_id at 0x1AD
    online_bytes = online_id.encode('ascii')[:16]
    data[0x1AD:0x1AD+17] = b'\x00' * 17  # Clear first
    data[0x1AD:0x1AD+len(online_bytes)] = online_bytes
    print(f"  Patched online_id: '{online_id}'")

    # Patch np_email at 0x1100
    np_email = f"{online_id}@a8.{country}.np.playstation.net"
    np_email_bytes = np_email.encode('ascii')[:64]
    data[0x1100:0x1100+65] = b'\x00' * 65  # Clear first
    data[0x1100:0x1100+len(np_email_bytes)] = np_email_bytes
    print(f"  Patched np_email: '{np_email}'")

    # Write output
    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"\nWrote {output_path} ({len(data)} bytes)")


def show_config_dat(filepath: str):
    """Show key fields from config.dat"""
    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"config.dat: {filepath}")
    print(f"  Size: {len(data)} bytes")
    print()

    # Parse key fields
    print("Key fields:")
    print(f"  [0x004] username:   '{data[0x04:0x14].rstrip(b'\x00').decode('ascii', errors='replace')}'")
    print(f"  [0x100] account_id: {data[0x100:0x108].hex()}")
    print(f"  [0x108] email:      '{data[0x108:0x148].rstrip(b'\x00').decode('ascii', errors='replace')}'")
    print(f"  [0x177] np_env:     '{data[0x177:0x187].rstrip(b'\x00').decode('ascii', errors='replace')}'")
    print(f"  [0x1AD] online_id:  '{data[0x1AD:0x1BE].rstrip(b'\x00').decode('ascii', errors='replace')}'")
    print(f"  [0x1BE] country:    '{data[0x1BE:0x1C0].rstrip(b'\x00').decode('ascii', errors='replace')}'")
    print(f"  [0x1C1] language:   '{data[0x1C1:0x1C3].rstrip(b'\x00').decode('ascii', errors='replace')}'")
    print(f"  [0x1C7] locale:     '{data[0x1C7:0x1D7].rstrip(b'\x00').decode('ascii', errors='replace')}'")
    print(f"  [0x1F4] field:      {struct.unpack_from('<I', data, 0x1F4)[0]}")
    print(f"  [0x1F8] signin_flag:{struct.unpack_from('<I', data, 0x1F8)[0]}")
    print(f"  [0x1100] np_email:  '{data[0x1100:0x1140].rstrip(b'\x00').decode('ascii', errors='replace')}'")
    print(f"  [0x1141] birthday:  '{data[0x1141:0x114C].rstrip(b'\x00').decode('ascii', errors='replace')}'")
    print(f"  [0x114C] token:     '{data[0x114C:0x118C].rstrip(b'\x00').decode('ascii', errors='replace')[:32]}...'")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} patch <template.dat> <output.dat> <username> [online_id]")
        print(f"  {sys.argv[0]} show <config.dat>")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} patch template/config.dat output/config.dat User1")
        print(f"  {sys.argv[0]} patch template/config.dat output/config.dat User1 MyOnlineId")
        print(f"  {sys.argv[0]} show output/config.dat")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'patch' and len(sys.argv) >= 5:
        template = sys.argv[2]
        output = sys.argv[3]
        username = sys.argv[4]
        online_id = sys.argv[5] if len(sys.argv) > 5 else None

        print(f"Patching config.dat...")
        print(f"  Template: {template}")
        print(f"  Output:   {output}")
        print()

        patch_config_dat(template, output, username, online_id)
        print()
        show_config_dat(output)

    elif cmd == 'show' and len(sys.argv) >= 3:
        show_config_dat(sys.argv[2])

    else:
        print("Invalid command or missing arguments")
        sys.exit(1)
