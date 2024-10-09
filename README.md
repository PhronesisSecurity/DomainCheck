# DNS Security Checker

This script checks various DNS security configurations for a given domain, including SPF, DMARC, DNSSEC, CAA, A, AAAA, NS, CNAME, and MX records. It also verifies the resolvability of these records to ensure they are correctly configured.

## Features

- **SPF Records**: Checks for the presence and validity of SPF records.
- **DMARC Records**: Checks for the presence and validity of DMARC records.
- **DNSSEC**: Verifies if DNSSEC is enabled.
- **CAA Records**: Checks for the presence of CAA records.
- **A and AAAA Records**: Checks for the presence and validity of A and AAAA records.
- **NS Records**: Verifies the resolvability of NS records and ensures they can handle DNS queries.
- **CNAME Records**: Brute forces CNAME records using a wordlist and checks their resolvability.
- **MX Records**: Checks for the presence and validity of MX records and ensures they resolve correctly.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/PhronesisSecurity/DomainCheck.git
    cd DomainCheck
    ```

2. Install the required Python packages:
    ```bash
    pip install dns.resolver colorama
    ```

## Usage
    ```bash
    python domaincheck.py
    ```
