# Subdomain Enumeration

A passive DNS resolution prototype that checks a small wordlist against a domain during an authorized assessment.

## Problem and objective

Security teams need to understand their externally visible DNS names. This tool demonstrates how candidate subdomains can be identified from DNS answers without probing services or exploiting hosts.

## Features

- Validates a DNS domain and candidate label syntax.
- Uses a local wordlist, bounded candidate count, modest concurrency, and DNS resolution.
- Reports resolved names and addresses; handles invalid input and lookup failures.
- Does not perform zone transfers, brute-force recursive expansion, or HTTP requests.

## Technology

Python 3.10+ standard library.

## Setup and run

```bash
python enumerate.py example.com --wordlist wordlist.txt
```

Only enumerate domains you own or have explicit authorization to assess. `example.com` is reserved for documentation; replace it with a domain in your authorized scope.

## How it works

Each valid word is joined to the supplied domain, resolved with the operating system's DNS resolver, and included if at least one address record is returned. Resolver behavior and caching affect results.

## Screenshots and demo

No screenshot or live demo is included. Use a domain in your authorized scope or a local test DNS zone.

## Tests

Run `python -m unittest discover -s tests -v` from this repository root.

## Security considerations

DNS queries are visible to your resolver and may be logged. Keep the wordlist small and follow the assessment scope. Absence of an answer does not prove a name does not exist.

## Future improvements

Add CNAME and AAAA reporting, CSV output, resolver selection, and scope allowlists backed by assessment records.
