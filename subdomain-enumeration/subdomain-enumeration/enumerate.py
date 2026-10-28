#!/usr/bin/env python3
"""Passive DNS candidate lookup for authorized security assessments."""
import argparse
import concurrent.futures
import ipaddress
import re
import socket

LABEL = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


def valid_domain(domain):
    domain = domain.rstrip(".")
    if len(domain) > 253 or "." not in domain:
        return False
    labels = domain.split(".")
    if any(not LABEL.fullmatch(label) for label in labels):
        return False
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        return True


def resolve(domain, label):
    fqdn = f"{label}.{domain}"
    try:
        records = sorted({item[4][0] for item in socket.getaddrinfo(fqdn, None, type=socket.SOCK_STREAM)})
        return fqdn, records
    except socket.gaierror:
        return fqdn, []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domain", help="authorized DNS domain")
    parser.add_argument("--wordlist", default="wordlist.txt")
    args = parser.parse_args()
    domain = args.domain.lower().rstrip(".")
    try:
        if not valid_domain(domain):
            raise ValueError("Enter a valid DNS domain (not an IP address).")
        with open(args.wordlist, encoding="utf-8") as stream:
            labels = sorted({line.strip().lower() for line in stream if line.strip() and not line.lstrip().startswith("#")})
        if not labels or len(labels) > 500:
            raise ValueError("Wordlist must contain 1–500 candidate labels.")
        if any(not LABEL.fullmatch(label) for label in labels):
            raise ValueError("Wordlist contains an invalid DNS label.")
        print(f"Passive DNS lookup for {len(labels)} names under {domain}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda word: resolve(domain, word), labels))
        found = [(name, addresses) for name, addresses in results if addresses]
        for name, addresses in found:
            print(f"{name}  {', '.join(addresses)}")
        print(f"Resolved {len(found)} of {len(labels)} candidates")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
