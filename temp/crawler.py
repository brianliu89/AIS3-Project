'''
爬蟲 
'''
import requests
from bs4 import BeautifulSoup
import re
import json
import time
import socket
import whois
import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode
from datetime import datetime


"""
Virustotal 
    USERNAME=XxXxXxX_0
    PASSWORD=(abc213)
"""
API_KEY = "f627d516b7ffc38e3a0dec14ae1c2f20943173ff0b75bedba0ff1935d63d54eb"

# get html
def get_html(url):
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        # r.encoding = r.apparent_encoding
        r.encoding = 'utf-8'
        return r.text
    except:
        raise "ERROR"

# judge domain or ip using re
def input_judge(user_input):
    if re.match(r'^https?:/{2}\w.+$', user_input):
        return "url"
    elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', user_input):
        return "ip"
    else:
        return 'Invalid input.'

# get domain ip
def get_ip(url):
    try:
        ip = socket.gethostbyname(url)
        return ip
    except:
        raise "ERROR"

import whois
from datetime import datetime

def get_whois_info(url):
    try:
        w = whois.whois(url)
        
        # Format creation dates
        formatted_creation_dates = []
        formatted_expiration_dates = []

        # Format creation dates
        for date in w.creation_date:
            if date is not None:
                formatted_creation_dates.append(date.strftime('%Y-%m-%d %H:%M:%S'))

        # Format expiration dates
        for date in w.expiration_date:
            if date is not None:
                formatted_expiration_dates.append(date.strftime('%Y-%m-%d %H:%M:%S'))

        formatted_creation_str = ', '.join(formatted_creation_dates)
        formatted_expiration_str = ', '.join(formatted_expiration_dates)

        return formatted_creation_str, formatted_expiration_str, w.registrar
    except:
        raise Exception("ERROR")


# Send a URL for analysis and get the report
# https://developers.virustotal.com/reference/url
def send_url_for_analysis(url):
    try:
        with virustotal_python.Virustotal(API_KEY) as vtotal:
            resp = vtotal.request("urls", data={"url": url}, method="POST")
            # Safe encode URL in base64 format
            # https://developers.virustotal.com/reference/url
            url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
            report = vtotal.request(f"urls/{url_id}")
            return report.data
    except virustotal_python.VirustotalError as err:
        raise "ERROR"


if __name__=='__main__':
    # input url
    #user_input = input('Input: ')
    user_input = "https://www.google.com"
    res = input_judge(user_input)
    #print(res)

    # whois
    creation_date, expiration_date, registrar = get_whois_info(user_input)

    print(f'''
        Creation date: {creation_date}\n 
        Expiration date: {expiration_date}\n
        Registrar: {registrar}\n
    ''')