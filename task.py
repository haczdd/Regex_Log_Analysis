import re
import json
import csv
from bs4 import BeautifulSoup
from collections import defaultdict

access_log_file = 'access_log.txt'
threat_feed_index = 'threat_feed.html'
url_status_report = 'url_status_report.txt'
malware_candidates_csv = 'malware_candidates.csv'
summary_report_file = 'summary_report.json'
alert_file = 'alert.json'  
pattern = r'\"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (http[s]?://[\w.-]+(?:/[^\s]*)?) HTTP/1\.1\" (\d{3})'

with open(access_log_file, 'r') as file:
    access_log = file.read()

matches = re.findall(pattern, access_log)

unique_urls = set()

error_counts = defaultdict(int)

with open("url_status_report.txt", "w") as url_status_file:
    for url, status_code in matches:
        if (url, status_code) not in unique_urls:
            unique_urls.add((url, status_code))
            url_status_file.write(f"URL: {url}, Status Code: {status_code}\n")
        if status_code == "404":
            error_counts[url] += 1

with open("malware_candidates.csv", "w", newline="") as csvfile:
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(["URL", "\t\t\t\t\t\t\t\t\t404 Count"])
    for url, count in error_counts.items():
        if count > 0:
            count = '\t\t'+str(count)
            csvwriter.writerow([url, count])


def remove_blacklisted_domains(file_name):
    with open(file_name, "r", encoding="utf-8") as file:
        content = file.read()

    soup = BeautifulSoup(content, "html.parser")

    ul_tag = soup.find("ul")
    removed_domains = []  # Silinmiş domenlər üçün siyahı
    if ul_tag:
        for li in ul_tag.find_all("li"):
            removed_domains.append(li.text.strip())  # Domen adını siyahıya əlavə et
        ul_tag.clear()  # `ul` elementini təmizlə

    with open(file_name, "w", encoding="utf-8") as file:
        file.write(str(soup))

    print(f"{file_name} faylı uğurla redaktə edildi və saxlanıldı!")
    return removed_domains  # Silinmiş domenlərin siyahısını qaytar


def generate_alerts(removed_domains):
    alerts = []

    for url, status_code in matches:
        for domain in removed_domains:
            if domain in url:
                alerts.append({
                    "url": url,
                    "status_code": status_code,
                    "domain": domain
                })

    with open(alert_file, "w", encoding="utf-8") as json_file:
        json.dump(alerts, json_file, indent=4)

    print(f"{alert_file} faylı uğurla yaradıldı!")


def generate_summary_report(removed_domains):
    # access_log.txt faylını oxumaq
    with open(access_log_file, 'r', encoding='utf-8') as file:
        access_logs = file.readlines()

    # Statistik məlumatları hazırlamaq
    total_urls = 0
    get_requests = 0
    post_requests = 0
    error_404_count = 0
    unique_ips = set()
    domain_access_counts = defaultdict(int)

    for log in access_logs:
        match = re.search(r'"(GET|POST) (http[s]?://[\w.-]+)', log)
        if match:
            method, url = match.groups()
            total_urls += 1
            if method == "GET":
                get_requests += 1
            elif method == "POST":
                post_requests += 1

            for domain in removed_domains:
                if domain in url:
                    domain_access_counts[domain] += 1

        # 404 status kodunu yoxlamaq
        if ' 404 ' in log:
            error_404_count += 1

        # Unikal IP-ləri toplamaq
        ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', log)
        if ip_match:
            unique_ips.add(ip_match.group(1))

    # Xülasəni hazırlamaq
    summary = {
        "blacklisted_domains_summary": {
            "total_blacklisted_domains": len(removed_domains),
            "domain_access_counts": domain_access_counts
        },
        "error_404_summary": {
            "total_404_requests": error_404_count,
            "ip_addresses": list(unique_ips)
        },
        "unique_ips": {
            "total_unique_ips": len(unique_ips),
            "ip_list": list(unique_ips)
        },
        "url_statistics": {
            "total_urls": total_urls,
            "get_requests": get_requests,
            "post_requests": post_requests
        }
    }

    # JSON faylına yazmaq
    with open(summary_report_file, 'w', encoding='utf-8') as json_file:
        json.dump(summary, json_file, indent=4)

    print(f"{summary_report_file} faylı uğurla yaradıldı!")


# Proqramın icrası
removed_domains = remove_blacklisted_domains(threat_feed_index)
generate_alerts(removed_domains)  # Alertlər yaradılır
generate_summary_report(removed_domains)  # Xülasə yaradılır
