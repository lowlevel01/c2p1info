# c2p1info
Retrieves useful information to detect C2 pivot points to be used in queries on platforms (e.g. via Shodan, Censys, ...)

``
usage: c2p1nfo.py [-h] IP P [P ...]

C2 Pivoting information retriever.

positional arguments:
  IP          IP address to process
  P           List of ports to process

options:
  -h, --help  show this help message and exit
``

### Retrived information:
- ASN information
- DNS Records: PTR Name and A Records
- ISP
- Banner sha256 hash
- HTTP SHA256 hash
- SSL Fingerprint
- SSL Certificate
- Favicon SHA256 Hash
- Image names
- SSH Fingerprint
