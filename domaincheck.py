import dns.resolver
from dns.exception import DNSException
from colorama import Fore, Style

# Set the subdomain list file and wordlist file
SUBDOMAIN_LIST_FILE = 'subdomains.txt'
WORDLIST_FILE = 'wordlist.txt'

def check_domain_security(domain, subdomain_list_path, wordlist_path):
    print(f"\nChecking security configurations for {domain}...\n")

    results = {
        'SPF': check_spf(domain),
        'DMARC': check_dmarc(domain),
        'DNSSEC': check_dnssec(domain),
        'CAA': check_caa(domain),
        'A Records': check_a_records(domain),
        'AAAA Records': check_aaaa_records(domain),
        'NS Records': check_ns_records(domain),
        'CNAME Records': check_cname_records(domain, subdomain_list_path, wordlist_path),
        'MX Records': check_mx_records(domain),
    }

    print("\n--- DNS Security Report ---")
    for key, value in results.items():
        if key == 'CNAME Records' and value:
            print(f"{key}:")
            for cname in value:
                print(f"  {cname}")
        else:
            print(f"{key}: {value}")

def check_spf(domain):
    try:
        spf_records = dns.resolver.resolve(domain, 'TXT')
        for record in spf_records:
            if str(record).startswith('v=spf1'):
                result = f"{Fore.GREEN}SPF record found: {record}{Style.RESET_ALL}"
                check_spf_ips(record)
                return result
        return f"{Fore.RED}No SPF record found.{Style.RESET_ALL}"
    except DNSException as e:
        return f"{Fore.RED}Error checking SPF: {str(e)}{Style.RESET_ALL}"

def check_dmarc(domain):
    try:
        dmarc_record = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        return f"{Fore.GREEN}DMARC record found: {', '.join([str(record) for record in dmarc_record])}{Style.RESET_ALL}"
    except DNSException:
        return f"{Fore.YELLOW}No DMARC record found.{Style.RESET_ALL}"

def check_dnssec(domain):
    try:
        dnssec_record = dns.resolver.resolve(domain, 'DS')
        if dnssec_record:
            return f"{Fore.GREEN}DNSSEC Check: Enabled{Style.RESET_ALL}"
        return f"{Fore.RED}DNSSEC Check: Not enabled{Style.RESET_ALL}"
    except DNSException:
        return f"{Fore.RED}DNSSEC Check: Not enabled{Style.RESET_ALL}"

def check_caa(domain):
    try:
        caa_record = dns.resolver.resolve(domain, 'CAA')
        return f"{Fore.GREEN}CAA record found: {', '.join([str(record) for record in caa_record])}{Style.RESET_ALL}"
    except DNSException:
        return f"{Fore.YELLOW}No CAA record found.{Style.RESET_ALL}"

def check_a_records(domain):
    try:
        a_records = dns.resolver.resolve(domain, 'A')
        a_records_found = [str(record) for record in a_records]
        return (f"{Fore.GREEN}A record(s) found: {a_records_found}{Style.RESET_ALL}"
                if a_records_found else f"{Fore.RED}No A records found.{Style.RESET_ALL}")
    except DNSException as e:
        return f"{Fore.RED}Error checking A records: {str(e)}{Style.RESET_ALL}"

def check_aaaa_records(domain):
    try:
        aaaa_records = dns.resolver.resolve(domain, 'AAAA')
        aaaa_records_found = [str(record) for record in aaaa_records]
        return (f"{Fore.GREEN}AAAA record(s) found: {aaaa_records_found}{Style.RESET_ALL}"
                if aaaa_records_found else f"{Fore.RED}No AAAA records found.{Style.RESET_ALL}")
    except DNSException:
        return f"{Fore.YELLOW}No AAAA records found.{Style.RESET_ALL}"

def check_ns_records(domain):
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        ns_records_found = [str(record) for record in ns_records]
        result = (f"{Fore.GREEN}NS records found: {ns_records_found}{Style.RESET_ALL}"
                  if ns_records_found else f"{Fore.RED}No NS records found.{Style.RESET_ALL}")

        for ns_record in ns_records_found:
            check_ns_resolvability(ns_record)
        return result
    except DNSException as e:
        return f"{Fore.RED}Error checking NS records: {str(e)}{Style.RESET_ALL}"

def check_cname_records(domain, subdomain_list_path, wordlist_path):
    cname_records_found = []
    try:
        with open(subdomain_list_path, 'r') as f:
            subdomains = f.read().splitlines()

        print(f"{Fore.GREEN}CNAME Records for {domain}:{Style.RESET_ALL}")
        for subdomain in subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                cname_records = dns.resolver.resolve(full_domain, 'CNAME')
                for record in cname_records:
                    cname_record_str = f"{full_domain} -> {record}"
                    cname_records_found.append(cname_record_str)
                    print(f"{Fore.GREEN}Found CNAME: {cname_record_str}{Style.RESET_ALL}")
                    check_cname_target(record)
            except DNSException as e:
                if "does not exist" not in str(e):
                    print(f"{Fore.RED}Error checking CNAME records for {full_domain}: {str(e)}{Style.RESET_ALL}")

        # Brute force CNAME records using the wordlist
        with open(wordlist_path, 'r') as f:
            words = f.read().splitlines()

        for word in words:
            full_domain = f"{word}.{domain}"
            try:
                cname_records = dns.resolver.resolve(full_domain, 'CNAME')
                for record in cname_records:
                    cname_record_str = f"{full_domain} -> {record}"
                    cname_records_found.append(cname_record_str)
                    print(f"{Fore.GREEN}Found CNAME: {cname_record_str}{Style.RESET_ALL}")
                    check_cname_target(record)
            except DNSException as e:
                if "does not exist" not in str(e):
                    print(f"{Fore.RED}Error checking CNAME records for {full_domain}: {str(e)}{Style.RESET_ALL}")

    except FileNotFoundError:
        print(f"{Fore.RED}Error: The subdomain list file '{subdomain_list_path}' not found.{Style.RESET_ALL}")

    return cname_records_found

def check_mx_records(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_records_found = [str(record.exchange) for record in mx_records]
        result = (f"{Fore.GREEN}MX record(s) found: {mx_records_found}{Style.RESET_ALL}"
                  if mx_records_found else f"{Fore.RED}No MX records found.{Style.RESET_ALL}")

        for mx_record in mx_records_found:
            check_mx_resolvability(mx_record)
        return result
    except DNSException as e:
        return f"{Fore.RED}Error checking MX records: {str(e)}{Style.RESET_ALL}"

def check_ns_resolvability(ns_record):
    try:
        ns_ip = dns.resolver.resolve(ns_record, 'A')
        print(f"{Fore.GREEN}NS {ns_record} resolves to: {[str(ip) for ip in ns_ip]}{Style.RESET_ALL}")

        resolver = dns.resolver.Resolver()
        resolver.nameservers = [str(ip) for ip in ns_ip]
        response = resolver.resolve(TARGET_DOMAIN, 'A')
        print(f"{Fore.GREEN}Successfully queried {ns_record} for {TARGET_DOMAIN}: {response}{Style.RESET_ALL}")
    except DNSException as e:
        print(f"{Fore.RED}Error querying {ns_record}: {str(e)}{Style.RESET_ALL}")

def check_cname_target(cname_record):
    try:
        cname_target = str(cname_record)
        target_ip = dns.resolver.resolve(cname_target, 'A')
        print(f"{Fore.GREEN}CNAME target {cname_target} resolves to: {[str(ip) for ip in target_ip]}{Style.RESET_ALL}")
    except DNSException as e:
        print(f"{Fore.RED}CNAME target {cname_record} does not resolve: {str(e)}{Style.RESET_ALL}")

def check_mx_resolvability(mx_record):
    try:
        mx_ip = dns.resolver.resolve(mx_record, 'A')
        print(f"{Fore.GREEN}MX {mx_record} resolves to: {[str(ip) for ip in mx_ip]}{Style.RESET_ALL}")
    except DNSException as e:
        print(f"{Fore.RED}MX {mx_record} does not resolve: {str(e)}{Style.RESET_ALL}")

def check_spf_ips(spf_record):
    spf_parts = str(spf_record).split()
    for part in spf_parts:
        if part.startswith('ip4:') or part.startswith('ip6:'):
            ip = part.split(':')[1]
            try:
                ip_res = dns.resolver.resolve(ip, 'A')
                print(f"{Fore.GREEN}SPF IP {ip} resolves to: {[str(ip) for ip in ip_res]}{Style.RESET_ALL}")
            except DNSException as e:
                print(f"{Fore.RED}SPF IP {ip} does not resolve: {str(e)}{Style.RESET_ALL}")

# Prompt for the domain to check
TARGET_DOMAIN = input("Enter the domain to check (e.g., example.com): ")

# Call the main function
check_domain_security(TARGET_DOMAIN, SUBDOMAIN_LIST_FILE, WORDLIST_FILE)
