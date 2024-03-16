import requests
import json

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

        print(f"是否公共IP: {'是' if is_public else '否'}")
        print(f"風險評分: {abuse_confidence_score}") # 這個範圍從 0 到 100。風險評分越高，表示該 IP 地址越有可能涉及惡意活動或濫用行為。
    else:
        print(f"無法取得IP位址 {ip_address} 的相關資訊。")

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

def scan_URL(API_KEY, url_to_scan):
    # 進行URL掃描
    scan_result = scan_url_with_virustotal(API_KEY, url_to_scan)
    scan_id = scan_result.get('scan_id')
    
    # 等待數秒後，再透過掃描ID查詢掃描報告
    if scan_id:
        scan_report = get_url_report(API_KEY, scan_id)

        # 只輸出部分資訊
        output = {
            'URL': scan_report.get('url'),
            #'Scan Date': scan_report.get('scan_date'),
            '總共掃描此網站的防毒軟體數量': scan_report.get('total'),   # 是指總共掃描的防毒引擎數量
            '認為此網站有害的防毒軟體數量': scan_report.get('positives')  # 表示有多少個防毒引擎檢測出該URL或檔案是有害的
        }

        formatted_report = json.dumps(output, indent=2, ensure_ascii=False)
        print(formatted_report)
    else:
        print("URL掃描失敗，請稍後再試。")

def scan_IP(ip_address, IPdata_api_key):
    # 取得 IP 位址的相關資訊
    ipdata_info = get_ipdata_info(ip_address, IPdata_api_key)

    # 顯示相關資訊
    print(f"IP 位址: {ipdata_info['ip']}")
    print(f"地理位置: {ipdata_info['city']}, {ipdata_info['region']}, {ipdata_info['country_name']}")
    print(f"緯度: {ipdata_info['latitude']}, 經度: {ipdata_info['longitude']}")
    print(f"語言: {ipdata_info['languages'][0]['name']}, 國家代碼: {ipdata_info['languages'][0]['native']}")
    print(f"時區: {ipdata_info['time_zone']['name']} ({ipdata_info['time_zone']['abbr']})")
    print(f"ASN: {ipdata_info['asn']['asn']} {ipdata_info['asn']['name']}")

    # 使用 API 查詢該 IP 位址的風險評估結果
    check_ip_abuse(ip_address, AbuseIPDB_api_key) 

if __name__ == '__main__':
    # 設定你的 IPdata API 金鑰
    IPdata_api_key = "2def34f3ebc9abf5c475b90e5d8c5399fb32dc64e90d04514de41b9b"
    # 要查詢的 IP 位址
    ip_address = "61.177.172.160"  # 這裡替換為你要查詢的 IP 位址  118.163.19.77

    # 設定你的 AbuseIPDB API 金鑰
    AbuseIPDB_api_key = "3e903d40fe34f8f6f773c8adbc19d2c8707aa063d186543c8f0c973037001c70ec45b4677f9f8002"

    # 設定你的 VirusTotal API 金鑰
    VirusTotal_api_key = '2a958acb6415e1faff944c93951107d9a12e374c92c23ec9f4896e8b20c9e662'
    # 要查詢的 URL
    url_to_scan = 'https://hackmd.io/'

    scan_URL(VirusTotal_api_key, url_to_scan)
    scan_IP(ip_address, IPdata_api_key)
    check_ip_abuse(ip_address, AbuseIPDB_api_key)