#!/usr/bin/env python3
"""Sign the ClawDefender threat feed manifest using Ed25519.

Usage:
    python sign-feed.py --key <private-key-file> [--feed-dir <path>]

The script reads feed/v1/manifest.json, signs it with the Ed25519 private key,
and writes the signature to feed/v1/signatures/latest.sig (hex-encoded).

If no key file is provided, a new keypair is generated and saved.

Dependencies:
    pip install PyNaCl
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.encoding import HexEncoder
except ImportError:
    print("Error: PyNaCl is required. Install with: pip install PyNaCl", file=sys.stderr)
    sys.exit(1)


def generate_keypair(output_dir: Path) -> SigningKey:
    """Generate a new Ed25519 keypair and save to files."""
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key

    private_path = output_dir / "feed-private.key"
    public_path = output_dir / "feed-public.key"

    private_path.write_bytes(signing_key.encode(encoder=HexEncoder))
    public_path.write_bytes(verify_key.encode(encoder=HexEncoder))

    private_path.chmod(0o600)

    print(f"Generated keypair:")
    print(f"  Private key: {private_path}")
    print(f"  Public key:  {public_path}")
    print(f"  Public key (hex): {verify_key.encode(encoder=HexEncoder).decode()}")

    return signing_key


def load_key(key_path: Path) -> SigningKey:
    """Load an Ed25519 private key from a hex-encoded file."""
    key_hex = key_path.read_bytes().strip()
    return SigningKey(key_hex, encoder=HexEncoder)


def sign_manifest(signing_key: SigningKey, manifest_path: Path, sig_path: Path) -> None:
    """Sign the manifest file and write the signature."""
    manifest_bytes = manifest_path.read_bytes()

    signed = signing_key.sign(manifest_bytes)
    signature_hex = signed.signature.hex()

    sig_path.write_text(signature_hex + "\n")

    print(f"Signed {manifest_path}")
    print(f"Signature written to {sig_path}")
    print(f"Signature (hex): {signature_hex[:64]}...")


def main():
    parser = argparse.ArgumentParser(description="Sign ClawDefender threat feed manifest")
    parser.add_argument("--key", type=Path, help="Path to Ed25519 private key (hex-encoded)")
    parser.add_argument("--generate-key", action="store_true", help="Generate a new keypair")
    parser.add_argument(
        "--feed-dir",
        type=Path,
        default=Path(__file__).parent.parent / "feed" / "v1",
        help="Path to feed/v1 directory",
    )

    args = parser.parse_args()

    if args.generate_key:
        key_dir = Path(__file__).parent.parent
        signing_key = generate_keypair(key_dir)
    elif args.key:
        if not args.key.exists():
            print(f"Error: Key file not found: {args.key}", file=sys.stderr)
            sys.exit(1)
        signing_key = load_key(args.key)
    else:
        print("Error: Either --key or --generate-key is required.", file=sys.stderr)
        sys.exit(1)

    manifest_path = args.feed_dir / "manifest.json"
    sig_path = args.feed_dir / "signatures" / "latest.sig"

    if not manifest_path.exists():
        print(f"Error: Manifest not found: {manifest_path}", file=sys.stderr)
        sys.exit(1)

    sig_path.parent.mkdir(parents=True, exist_ok=True)
    sign_manifest(signing_key, manifest_path, sig_path)

    print("\nDone. Feed signed successfully.")


if __name__ == "__main__":
    main()
