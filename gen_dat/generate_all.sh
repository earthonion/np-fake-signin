#!/bin/bash
# Generate all PS4 NP dat files for a given username

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$1" ]; then
    echo "Usage: $0 <username> [output_dir]"
    echo ""
    echo "Generates auth.dat, account.dat, token.dat, and config.dat"
    exit 1
fi

USERNAME="$1"
OUTPUT_DIR="${2:-.}"

mkdir -p "$OUTPUT_DIR"

echo "Generating NP files for user: $USERNAME"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Generate auth.dat
echo "Creating auth.dat..."
python3 "$SCRIPT_DIR/generate_auth_dat.py" "$OUTPUT_DIR/auth.dat"

# Generate account.dat
echo "Creating account.dat..."
python3 "$SCRIPT_DIR/generate_account_dat.py" generate "$OUTPUT_DIR/account.dat" "$USERNAME"

# Generate token.dat
echo "Creating token.dat..."
python3 "$SCRIPT_DIR/generate_token_dat.py" generate "$OUTPUT_DIR/token.dat"

# Generate config.dat
echo "Creating config.dat..."
python3 "$SCRIPT_DIR/generate_config_dat.py" generate "$OUTPUT_DIR/config.dat" "$USERNAME"

echo ""
echo "Done! Generated files:"
ls -la "$OUTPUT_DIR"/*.dat
