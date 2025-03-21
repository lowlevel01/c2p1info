import requests
import socket
import ssl
import hashlib
from ipwhois import IPWhois
import base64
import mmh3
import paramiko
import logging
import dns.resolver
import argparse
import re

logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)


def compute_hash(data):
    return "sha256:" + hashlib.sha256(data.encode()).hexdigest()



def get_asn(ip):
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        asn = results.get('asn', 'N/A')
        asn_description = results.get('asn_description', 'N/A')
        return asn, asn_description
    except Exception as e:
        return None


def get_http_body_hash(ip, port):
    try:
        url = f'http://{ip}:{port}'
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            body = response.text
            body_hash = compute_hash(body)
            return str(body_hash)
        else:
            return f'Non-200 status code: {response.status_code}'
    except Exception as e:
        return None
    
def get_banner_hash(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode().strip()
            return compute_hash(banner)
    except Exception as e:
        return None

def get_ssl_certificate(ip, port):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return None

def get_favicon_hash(ip, port):
    try:
        url = f'http://{ip}:{port}/favicon.ico'
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            favicon = response.content
            favicon_base64 = base64.encodebytes(favicon)
            favicon_hash = mmh3.hash(favicon_base64)
            return str(favicon_hash)
        else:
            return f'Non-200 status code: {response.status_code}'
    except Exception as e:
        return None

def get_ssh_fingerprint(hostname, port):
    try:
        transport = paramiko.Transport((hostname, port))
        transport.connect()

        host_key = transport.get_remote_server_key()
        transport.close()

        key_bytes = host_key.asbytes()
        sha256_digest = hashlib.sha256(key_bytes).digest()
        fingerprint = base64.b64encode(sha256_digest).decode('utf-8').strip()

        return str(fingerprint)
    except Exception as e:
        return None
def get_ssl_fingerprint(hostname, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
        
        fingerprint = compute_hash(der_cert)
        return fingerprint.upper()
    except Exception as e:
        return None

def get_dns_records(ip_address):
    try:
        ptr_name = socket.getfqdn(ip_address)
        
        a_records = dns.resolver.resolve(ptr_name, 'A') if ptr_name else []
        a_addresses = [str(record) for record in a_records]
        
        return ptr_name, a_addresses
    except (socket.herror, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        return None

def get_isp(ip_address):
    try:
        response = requests.get(f'https://ipinfo.io/{ip_address}/json')
        data = response.json()
        isp_name = data.get('org', 'ISP not found')
        return isp_name
    except Exception as e:
        None

def get_image_filenames(ip_address, port):
    extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp']
    base_url = f'http://{ip_address}:{port}'
    image_files = []

    try:
        response = requests.get(base_url)
        if response.status_code == 200:
            for ext in extensions:
                # Create a pattern to match image filenames with the current extension
                pattern = rf'([a-zA-Z0-9_-]+){re.escape(ext)}'
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    image_files.append(f"{match}{ext}")
            if image_files:
                print(f"Found images: {image_files}")
            else:
                print("No images found.")
        else:
            return []
    except requests.RequestException as e:
        return []

    return image_files

    
def main():
    #target_ip = "1.1.1.1"
    #ports = [80, 443, 22, 21]

    parser = argparse.ArgumentParser(description='C2 Pivoting information retriever.')
    parser.add_argument('ip', metavar='IP', type=str, help='IP address to process')
    parser.add_argument('ports', metavar='P', type=int, nargs='+', help='List of ports to process')
    args = parser.parse_args()
    target_ip = args.ip
    ports = args.ports
    asn, asn_description = get_asn(target_ip)

    print(f'ASN: {asn}')
    print(f'ASN Description: {asn_description}')
    print('-' * 50)

    ptr_name, a_addresses = get_dns_records(target_ip)
    print(f"PTR Name: {ptr_name}")
    print(f"A Records: {a_addresses}")

    print('-' * 50)

    isp_name = get_isp(target_ip)
    print(f"ISP: {isp_name}")

    print('-' * 50)
    for port in ports:
        print(f'Port: {port}')


        banner_hash = get_banner_hash(target_ip, port)
        if 'None' not in str(banner_hash):
            print(f'Banner Hash: {banner_hash}')

        body_hash = get_http_body_hash(target_ip, port)
        if 'None' not in str(body_hash):
            print(f'HTTP Body Hash: {body_hash}')

        ssl_fingerprint = get_ssl_fingerprint(target_ip, port)
        if 'None' not in str(ssl_fingerprint):
            print(f'SSL Fingerprint Hash: {ssl_fingerprint}')

        ssl_certificate = get_ssl_certificate(target_ip, port)
        if 'None' not in str(ssl_certificate):
            print(f'SSL Certificate: '+str(ssl_certificate))

        

        favicon_hash = get_favicon_hash(target_ip, port)
        if 'None' not in str(favicon_hash):
            print(f'Favicon mmh3 Hash: {favicon_hash}')

        images = get_image_filenames(target_ip, port)
        for image in images:
            print(f"Image: {image}")

        ssh_fingerprint = get_ssh_fingerprint(target_ip, port)
        if 'None' not in str(ssh_fingerprint):
            print(f'SSH Fingerprint: {ssh_fingerprint}')
        print('-' * 50)

if __name__ == "__main__":
    main()