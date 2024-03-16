"""
Method template for url to ip
"""
from urllib.parse import urlparse
import socket

def url2ip(url):
    try: # check if we can get ip
        domain = urlparse(url).netloc
        return socket.gethostbyname(domain)
    except:
        return "Invalid"