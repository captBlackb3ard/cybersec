import re
import sys
import os
import quopri
import hashlib
import ipaddress
import requests
import email
import logging
import whois
import tldextract
from datetime import datetime
from urllib.parse import urlparse

"""
Script designed to aid email forensic analysis by extracting various artefacts from email eml files - IP addresses, URLs, Domains, and attachments. 
Based on MalwareCube's Email IOC Extractor - https://github.com/MalwareCube/Email-IOC-Extractor/tree/main

Version 1.2
"""

#Global Timestamp variable
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")

# -----------CLI Colour-----------
class Colors:
    RED = '\033[31m'
    GREEN = '\033[32m'
    RESET = '\033[0m' # Resets all formatting

# -----------Setup Logging and Output Directories-----------

def setup_environment():
    # Create results folder
    output_folder = os.path.join( f"eioc_results_analysis_{timestamp}")
    os.makedirs(output_folder, exist_ok=True)
    # Added logging
    log_file = os.path.join(output_folder, "error.log")
    logging.basicConfig(
        filename=log_file,
        level=logging.ERROR,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    return output_folder

def print_and_write(message, file_path):
    print(message)
    with open(file_path, "a") as output:
        output.write(message+"\n")

# -----------Email Parsing Functions-----------

def read_file(file_path):
    with open(file_path, 'rb') as file:
        content = file.read()
    parser = email.parser.BytesParser()
    msg = parser.parsebytes(content)
    return msg

def extract_ips(email_message):
    ips = set()
    for header_name, header_value in email_message.items():
        ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header_value))
    for part in email_message.walk():
        if part.get_content_type() in ['text/plain', 'text/html']:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8', errors='ignore')
            ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', payload))
    valid_ips = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
        except ValueError:
            continue
    return list(set(valid_ips))

def extract_urls(email_message):
    urls = set()
    for part in email_message.walk():
        if part.get_content_type() in ['text/plain', 'text/html']:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8', errors='ignore')
            urls.update(re.findall(r'https?:\/\/(?:[\w\-]+\.)+[a-z]{2,}(?:\/[\w\-\.\/?%&=]*)?', payload))
    return list(urls)

def extract_domains_from_urls(urls):
    domains = set()
    for url in urls:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if domain:
            domains.add(domain.lower())
    return list(domains)

def get_domain_whois(domain):
    try:
        whois_rs = whois.whois(domain)
        create_date = ""
        expire_date = ""
        if isinstance(whois_rs.creation_date, list):
            #WHOIS sometimes returns a list dateime objects 
            create_date = whois_rs.creation_date[0]
            expire_date = whois_rs.expiration_date[0]
            return {
                'Domain': domain,
                'Registrar': whois_rs.registrar,
                'Creation Date': str(create_date),
                'Expiration Date': str(expire_date),
                'Country': whois_rs.country
            }
        else:
            return {
                'Domain': domain,
                'Registrar': whois_rs.registrar,
                'Creation Date': str(whois_rs.creation_date),
                'Expiration Date': str(whois_rs.expiration_date),
                'Country': whois_rs.country
            }
    except Exception as e:
        logging.error(f"WHOIS lookup failed for {domain}: {e}", exc_info=True)
        return {'Domain': domain, 'Error': 'WHOIS lookup failed'}

def is_root_domain(domain_string: str) -> bool:
    extracted = tldextract.extract(domain_string)
    return not bool(extracted.subdomain)

def get_root_domain_if_subdomain(domain_string: str):
    extracted = tldextract.extract(domain_string)
    if not extracted.domain or not extracted.suffix: 
        return None
    if extracted.subdomain: #
        return f"{extracted.domain}.{extracted.suffix}" 
    # Already a root domain
    return None

def defang_ip(ip):
    return ip.replace('.', '[.]')

def defang_url(url):
    return url.replace('https://', 'hxxps[://]').replace('.', '[.]')

def extract_headers(email_message):
    headers_to_extract = [
        "Date",
        "Subject",
        "To",
        "From",
        "Reply-To",
        "Return-Path",
        "Message-ID",
        "X-Originating-IP",
        "X-Sender-IP",
        "Authentication-Results"
    ]
    headers = {}
    for key in email_message.keys():
        if key in headers_to_extract:
            headers[key] = email_message[key]
    return headers

def extract_attachments(email_message):
    attachments = []
    for part in email_message.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue
        filename = part.get_filename()
        if filename:
            attachments.append({
                'filename': filename,
                'md5': hashlib.md5(part.get_payload(decode=True)).hexdigest(),
                'sha1': hashlib.sha1(part.get_payload(decode=True)).hexdigest(),
                'sha256': hashlib.sha256(part.get_payload(decode=True)).hexdigest()
            })
    return attachments

def is_reserved_ip(ip):
    private_ranges = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
    ]
    reserved_ranges = [
        '0.0.0.0/8',
        '100.64.0.0/10',
        '169.254.0.0/16',
        '192.0.0.0/24',
        '192.0.2.0/24',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/4', 
        '240.0.0.0/4',
    ]
    for r in private_ranges + reserved_ranges:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(r):
            return True
    return False

def ip_lookup(ip, abuseipdb_key=None):
    if is_reserved_ip(ip):
        return None
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url, timeout=5)
        data = response.json() if response.status_code == 200 else {}
        result = {
            'IP': data.get('ip', ''),
            'City': data.get('city', ''),
            'Region': data.get('region', ''),
            'Country': data.get('country', ''),
            'Location': data.get('loc', ''),
            'ISP': data.get('org', ''),
            'Postal Code': data.get('postal', '')
        }
        if abuseipdb_key:
            headers = {'Key': abuseipdb_key, 'Accept': 'application/json'}
            abuse_resp = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90", headers=headers)
            if abuse_resp.status_code == 200:
                abuse_data = abuse_resp.json().get('data', {})
                result['Abuse Confidence Score'] = abuse_data.get('abuseConfidenceScore', 'N/A')
        return result
    except Exception as e:
        logging.error(f"IP Lookup failed for {ip}: {e}")
        return None


# -----------Main Execution-----------

def main(file_path, abuseipdb_key=None):
    output_dir = setup_environment()
    try:
        email_message = read_file(file_path)
        filename = timestamp + "-email_analysis_ioc_report.txt"
        output_file_path = os.path.join(output_dir, filename)

        ips = extract_ips(email_message)
        urls = extract_urls(email_message)
        headers = extract_headers(email_message)
        attachments = extract_attachments(email_message)
        urls_domains = extract_domains_from_urls(urls)
        
        # Write Results to File
        with open(output_file_path, "w") as output:
            print("\n") ## Start off on a new line
            print_and_write("************************************************************", output_file_path)
            print_and_write("Email IOC Extraction Report: " + timestamp, output_file_path)
            print_and_write("************************************************************", output_file_path)
            ## Headers 
            print_and_write("\nExtracted Headers:", output_file_path)
            print_and_write("====================================", output_file_path)
            for key, value in headers.items():
                print_and_write(key + ": " + value, output_file_path)

            ## IP Addresses
            print_and_write("\nExtracted IP Addresses:", output_file_path)
            print_and_write("====================================", output_file_path)
            for ip in ips:
                defanged = defang_ip(ip)
                info = ip_lookup(ip, abuseipdb_key)
                if info:
                    #output.write(f"{defanged} - {info.get('City')}, {info.get('Region')}, {info.get('Country')}, ISP: {info.get('ISP')}")
                    print_and_write(defanged + " - " + info.get('City')+ " - " + info.get('Region') + " - " + info.get('Country') + " - " + info.get('ISP'), output_file_path)
                    if 'Abuse Confidence Score' in info:
                        print_and_write("Abuse Score: " + str(info['Abuse Confidence Score']), output_file_path)
                else:
                    print_and_write(defanged, output_file_path)
                    
            ## URLs
            print_and_write("\nExtracted URLs:", output_file_path)
            print_and_write("====================================", output_file_path)
            for url in urls:
                print_and_write(defang_url(url), output_file_path)
            
            ## Domains
            print_and_write("\nExtracted Domains:", output_file_path)
            print_and_write("====================================", output_file_path)
            for domain in urls_domains:
                print_and_write("WHOIS Results: " + defang_url(domain), output_file_path)
                root_dom = ""
                if bool(is_root_domain(domain)):
                    root_dom = domain
                else:
                    root_dom = get_root_domain_if_subdomain(domain)       
                whois_rs = get_domain_whois(root_dom)
                if "Error" in whois_rs:
                    print_and_write("WHOIS lookup failed; try performing lookup manually.", output_file_path)
                else:
                    print_and_write("-Registrar: " + whois_rs['Registrar'], output_file_path)
                    print_and_write("-Creation Date: " + whois_rs['Creation Date'], output_file_path)
                    print_and_write("-Expiration Date: " + whois_rs['Expiration Date'], output_file_path)

            ## Attachments
            print_and_write("\nExtracted Attachments:", output_file_path)
            print_and_write("====================================", output_file_path)
            for att in attachments:
                print_and_write("Filename: " + att['filename'], output_file_path)
                print_and_write("MD5: " + att['md5'], output_file_path)
                print_and_write("SHA1: " + att['sha1'], output_file_path)
                print_and_write("SHA256: " + att['sha256'], output_file_path)
            
        print(f"\n\n"+Colors.GREEN +"[+]" + Colors.RESET + " Analysis completed. Output written to: "+output_file_path + "\n")

    except Exception as e:
        logging.error(f"Unhandled exception: {e}", exc_info=True)
        print(f" " + Colors.RED + "[!]" + Colors.RESET + " Error occurred. See error log in: "+ output_dir +"\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <email_file> [ABUSEIPDB_API_KEY]")
        sys.exit(1)

    file_path = sys.argv[1]
    abuseipdb_key = sys.argv[2] if len(sys.argv) > 2 else None
    main(file_path, abuseipdb_key)
