import requests
import json
from geopy.geocoders import Nominatim
import url2ip
from datetime import datetime
import whois
from secret import IPdata_api_key,AbuseIPDB_api_key,VirusTotal_api_key
from bs4 import BeautifulSoup

def get_ipdata_info(ip_address, api_key):
    url = f"https://api.ipdata.co/{ip_address}?api-key={api_key}"
    response = requests.get(url)
    data = response.json()

    return data

def check_ip_abuse(ip_address, api_key):
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90"  # 可選：限制檢查報告的最大天數，此處設置為90天
    }

    response = requests.get(url, headers=headers, params=params)
    data = response.json()

    if data['data']:
        is_public = data['data']['isPublic']
        abuse_confidence_score = data['data']['abuseConfidenceScore']
        output = f"是否公共IP: {'是' if is_public else '否'}\n" + f"風險評分: {abuse_confidence_score}\n"
        #print(f"是否公共IP: {'是' if is_public else '否'}")
        #print(f"風險評分: {abuse_confidence_score}") 
        #這個範圍從 0 到 100。風險評分越高，表示該 IP 地址越有可能涉及惡意活動或濫用行為。
    else:
        output = f"無法取得IP位址 {ip_address} 的相關資訊。\n"
        #print(f"無法取得IP位址 {ip_address} 的相關資訊。")
    return output

def scan_url_with_virustotal(api_key, url_to_scan):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': api_key, 'url': url_to_scan}
    response = requests.post(url, data=params)
    return response.json()

def get_url_report(api_key, resource):
    url = f'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': api_key, 'resource': resource}
    response = requests.get(url, params=params)
    return response.json()

def get_address_from_coordinates(latitude, longitude):
    geolocator = Nominatim(user_agent="reverse_geocoder")
    location = geolocator.reverse((latitude, longitude), exactly_one=True)

    if location:
        return location.address
    else:
        return "Error: Address not found."

def get_dates_info(url):
    try:
        w = whois.whois(url)

        # Format creation dates
        formatted_creation_dates = []
        formatted_expiration_dates = []

        # Format creation dates
        for date in w.creation_date:
            formatted_creation_dates.append(date.strftime('%Y-%m-%d %H:%M:%S'))

        # Format expiration dates
        for date in w.expiration_date:
            formatted_expiration_dates.append(date.strftime('%Y-%m-%d %H:%M:%S'))

        formatted_creation_str = ', '.join(formatted_creation_dates)
        formatted_expiration_str = ', '.join(formatted_expiration_dates)

        return f"創建日期: {formatted_creation_str}\n到期日期: {formatted_expiration_str}\n註冊者: {w.registrar}"
        
    except:
        raise "ERROR"

def get_keywords_info(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Get website title
            title = soup.title.string if soup.title else "No title found on the website."

            # Get meta keywords
            meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
            keywords = meta_keywords.get('content') if meta_keywords else "."

            # strcat keywords
            all_keyword = title + keywords

            return all_keyword
        else:
            return f"Failed to fetch the webpage. Status code: {response.status_code}", ""
    except requests.exceptions.RequestException as e:
        return f"Error: {e}", ""

def scan_URL(API_KEY, url_to_scan):
    # 進行URL掃描
    scan_result = scan_url_with_virustotal(API_KEY, url_to_scan)
    scan_id = scan_result.get('scan_id') # scan_id replace with 參數
    
    # 等待數秒後，再透過掃描ID查詢掃描報告
    if scan_id:
        scan_report = get_url_report(API_KEY, scan_id)
        # 只輸出部分資訊
        output = "總共掃描此網站的防毒軟體數量:" + str(scan_report.get('total')) + "\n認為此網站有害的防毒軟體數量:" + str(scan_report.get('positives'))

    else:
        output = "URL掃描失敗，請稍後再試。"
    return output

def scan_IP(ip_address, IPdata_api_key):
    # 取得 IP 位址的相關資訊
    ipdata_info = get_ipdata_info(ip_address, IPdata_api_key)
    output = f"基本資訊: \n" + f"地理位置: {ipdata_info['city']}, {ipdata_info['region']}, {ipdata_info['country_name']}\n" + f"緯度: {ipdata_info['latitude']}, 經度: {ipdata_info['longitude']}\n" + f"語言: {ipdata_info['languages'][0]['name']}, 國家代碼: {ipdata_info['languages'][0]['native']}\n" + f"時區: {ipdata_info['time_zone']['name']} ({ipdata_info['time_zone']['abbr']})\n" + f"ASN: {ipdata_info['asn']['asn']} {ipdata_info['asn']['name']}\n"
    country = f"{ipdata_info['country_name']}\n"
    # 顯示相關資訊
    #print(f"IP 位址: {ipdata_info['ip']}")
    #print(f"地理位置: {ipdata_info['city']}, {ipdata_info['region']}, {ipdata_info['country_name']}")
    #print(f"緯度: {ipdata_info['latitude']}, 經度: {ipdata_info['longitude']}")
    #print(f"語言: {ipdata_info['languages'][0]['name']}, 國家代碼: {ipdata_info['languages'][0]['native']}")
    #print(f"時區: {ipdata_info['time_zone']['name']} ({ipdata_info['time_zone']['abbr']})")
    #print(f"ASN: {ipdata_info['asn']['asn']} {ipdata_info['asn']['name']}")

    return output,ipdata_info['country_name'],ipdata_info['latitude'], ipdata_info['longitude']

def grab_url(url_to_scan,Label):
    if Label == "Domain":
        ipaddr = url2ip.url2ip(url_to_scan)
        report = "URL: " + url_to_scan + "\nIP 位址: " + str(ipaddr) + "\n"
    elif Label == "IP":
        ipaddr = url_to_scan
        report = "URL: https://" + str(ipaddr) + "/\nIP 位址: " + str(ipaddr) + "\n"
    else:
        return "syntex error"

    # scan ip address
    text,country,la,lo = scan_IP(ipaddr, IPdata_api_key)
    
    # 基本資訊
    report += text

    # 網域資訊
    report += "\n網域資訊:\n" + get_dates_info(url_to_scan) + "\n"

    # 安全性評估
    report += "\n安全性評估:\n" + check_ip_abuse(ipaddr, AbuseIPDB_api_key) + scan_URL(VirusTotal_api_key,url_to_scan) + "\n"

    # 內容關鍵字
    report += "\n內容關鍵字:\n" + get_keywords_info(url_to_scan)

    # print(report)
    return report,country,la,lo

if __name__=='__main__':
    url_to_scan = "https://docs.google.com/document/d/1s5u-4bw_hwKmhtpPA6pAalNF5Km91mLmdwMkxAUA1AE/mobilebasic#h.2a4ttduijnt4"
    ipaddr = url2ip.url2ip(url_to_scan)
    report = "URL: " + url_to_scan + "\nIp Address: " + str(ipaddr) + "\n"
    text,country,la,lo = scan_IP(ipaddr, IPdata_api_key)
    report += text + scan_URL(VirusTotal_api_key,url_to_scan)
    address = get_address_from_coordinates(la,lo)

    # print(report)
    # print(country)
    # print(la,lo)
    # print(address)
    grab_url(url_to_scan,"Domain")