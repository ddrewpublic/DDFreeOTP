#!/usr/bin/env python3
"""
andotp_to_freeotp.py
--------------------
Convert an andOTP-exported JSON (list of tokens) into a FreeOTP+ backup file.

What it does
============
* Reads an andOTP token list from JSON
* Decodes each base32 secret to a byte array
* Emits a FreeOTP+ backup JSON with ``"tokens"`` and ``"tokenOrder"``

Typical usage
=============
    $ python andotp_to_freeotp.py /path/to/andotp.json > freeotp_plus_backup.json

Exit codes
==========
* 0: success
* 1: wrong Python version, bad CLI usage, or unreadable/invalid input

Note
====
* Output is written to STDOUT; redirect to a file to save.
* ``tokenOrder`` is populated as ``":[<label>]"`` entries to match the
  expected FreeOTP+ presentation order.

Author
======
    Daniel Drew
    Adapted from rich-murphey / freeotp-to-andotp to add andOTP to FreeOTP+
"""
import base64
import json
import sys


def convert_andotp_to_freeotp(andotp_item):
    """
    Convert one andOTP token dict to a FreeOTP+ token object.

    Parameters
    ----------
    andotp_item : dict
        A single token object from an andOTP export. Expected keys include
        ``"type"``, ``"algorithm"``, ``"digits"``, ``"period"``, ``"secret"``
        (base32 string), and optional ``"issuer"`` and ``"label"``.

    Returns
    -------
    dict
        A FreeOTP+ token object with fields:
        ``{"type","algo","digits","period","secret","counter","issuerExt","label"}``,
        where ``secret`` is a list of bytes and ``counter`` is initialized to 0.
    """
    freeotp_item = {
        "type": andotp_item["type"],
        "algo": andotp_item["algorithm"],
        "digits": andotp_item["digits"],
        "period": andotp_item["period"],
        "secret": [x for x in base64.b32decode(andotp_item["secret"])],
        "counter": 0,
        "issuerExt": andotp_item.get("issuer", ""),
        "label": andotp_item["label"]
    }
    return freeotp_item


def main():
    """
    CLI entry point.

    Behavior
    --------
    * Validates Python 3 and a single positional argument (input path)
    * Loads the andOTP JSON (list of tokens)
    * Converts each token to FreeOTP+ format
    * Emits a FreeOTP+ backup JSON to STDOUT with ``tokens`` and ``tokenOrder``
    """
    if sys.version_info.major < 3:
        print("This script requires Python 3.")
        sys.exit(1)
    if len(sys.argv) != 2:
        print("Usage: ./andotp_to_freeotp.py <filename>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        andotp_data = json.load(f)

    freeotp_tokens = [convert_andotp_to_freeotp(x) for x in andotp_data]
    freeotp_output = {
        "tokenOrder": [f":{x['label']}" for x in freeotp_tokens],
        "tokens": freeotp_tokens
    }

    print(json.dumps(freeotp_output, indent=2))


if __name__ == "__main__":
    main()
