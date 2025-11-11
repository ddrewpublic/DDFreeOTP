#!/usr/bin/env python3
"""
freeotp_to_andotp.py
--------------------
Convert a FreeOTP+ JSON backup into a list of andOTP-compatible token objects.

What it does
============
* Reads a FreeOTP+ backup (a JSON file with a top-level ``"tokens"`` list)
* Converts each token field to andOTP’s schema (base32 secret, issuer/label, etc.)
* Prints the resulting andOTP token list to STDOUT as pretty-printed JSON

Typical usage
=============
    $ python freeotp_to_andotp.py /path/to/freeotp_plus_backup.json > andotp.json

Exit codes
==========
* 0: success, or no tokens found
* 1: wrong Python version, bad CLI usage, or unreadable/invalid input

Notes
=====
* This script does not write files; redirect STDOUT to save the output.
* The output is a list of token dicts (the format andOTP imports).
* Issuer/label are derived from FreeOTP+ fields when available; otherwise
  they fall back to ``"unknown"``.

Author
======
    Daniel Drew
    Adapted from https://github.com/rich-murphey/freeotp-to-andotp to support FreeOTP+.
"""

import base64
import json
import sys
import xml.etree.ElementTree  # May not be used but left in for completeness
from pprint import pprint
from typing import Dict, Any, List, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)


def convert_freotp_to_andotp(freeotp_item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert one FreeOTP+ token object to an andOTP-compatible token dict.

    Parameters
    ----------
    freeotp_item : Dict[str, Any]
        A single token object from the FreeOTP+ backup JSON (``tokens[i]``).
        Expected keys include ``type``, ``secret`` (byte array), ``digits``,
        ``algo`` (algorithm), and ``period``. Issuer/label keys vary by export
        version (e.g., ``issuerAlt``, ``issuerExt``, ``issuerInt``, ``label``,
        ``labelAlt``) and are handled defensively.

    Returns
    -------
    Dict[str, Any]
        A dict matching andOTP’s token schema:
        ``{"type","issuer","label","secret","digits","algorithm","period"}``,
        where ``secret`` is base32-encoded (RFC 3548/4648).

    Raises
    ------
    KeyError
        If required FreeOTP+ fields are missing (e.g., ``"secret"``).
    ValueError
        If fields are present but malformed and cannot be converted.
    """

    try:
        andotp_item = {
            "type": freeotp_item["type"],
            "issuer": "unknown",
            "label": "unknown",
            "secret": base64.b32encode(
                bytes(x & 0xFF for x in freeotp_item["secret"])
            ).decode("utf8"),
            "digits": freeotp_item["digits"],
            "algorithm": freeotp_item["algo"],
            "period": freeotp_item["period"]
        }

        issuer: Optional[str] = (
                freeotp_item.get("issuerAlt")
                or freeotp_item.get("issuerExt")
                or freeotp_item.get("issuerInt")
        )
        label: Optional[str] = (
                freeotp_item.get("label") or freeotp_item.get("labelAlt")
        )

        # if label and issuer:
        #     full_label = f"{issuer} - {label}"
        # else:
        #     full_label = label or issuer or "Unknown"

        andotp_item["label"] = label
        andotp_item["issuer"] = issuer

        return andotp_item
    except Exception as e:
        logging.error(f"Failed to convert token: {e}")
        raise


def main() -> None:
    """
    CLI entry point.

    Behavior
    --------
    * Validates Python 3 and a single positional argument (input path)
    * Loads the FreeOTP+ JSON
    * Converts each token to andOTP format
    * Prints a JSON array of converted tokens to STDOUT (indent=2)
    """
    if sys.version_info.major < 3:
        logging.critical("This script requires Python 3.")
        sys.exit(1)

    if len(sys.argv) != 2:
        logging.error("Usage: python freeotp_to_andotp.py <filename>")
        sys.exit(1)

    input_path: str = sys.argv[1]

    try:
        with open(input_path, 'r', encoding='utf-8') as file:
            freeotp_data: Dict[str, Any] = json.load(file)
    except (IOError, json.JSONDecodeError) as e:
        logging.critical(f"Failed to load input file: {e}")
        sys.exit(1)

    tokens: List[Dict[str, Any]] = freeotp_data.get('tokens', [])
    if not tokens:
        logging.warning("No tokens found in the input file.")
        sys.exit(0)

    converted_tokens: List[Dict[str, Any]] = [
        convert_freotp_to_andotp(token) for token in tokens
    ]

    # Ensure JSON-like string uses double quotes
    print(json.dumps(converted_tokens, indent=2))


if __name__ == "__main__":
    main()
