import ssl
import socket
import requests
import re
import pandas as pd
from bs4 import BeautifulSoup


def get_ssl_certificate_info(hostname, port=443):
    """
    Retrieves and returns SSL/TLS certificate information for a given hostname.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except (socket.error, ssl.SSLError, ConnectionRefusedError) as e:
        # print(f"Error retrieving certificate for {hostname}:{port} - {e}")
        return None


def get_company_names(url):
    try:
        response = requests.get(url)
        if response.status_code != 200:
            # print("ไม่สามารถเข้าถึงเว็บได้")
            return ""

        soup = BeautifulSoup(response.text, "html.parser")

        # ค้นหา meta tag ที่เกี่ยวข้อง
        meta_tags = soup.find_all("meta")

        for tag in meta_tags:
            if tag.get("property") == "og:site_name":  # ดึงจาก Open Graph
                # print(f" og:site_name: {tag.get('content')}")
                return tag.get("content")
            elif tag.get("name") == "author":  # ดึงจาก meta author (บางเว็บใช้สำหรับบริษัท)
                # print(f" author: {tag.get('content')}")
                return tag.get("content")

        return ""
    except requests.exceptions.ConnectionError as e:
        print(e)
        return ""


# ฟังก์ชันเปรียบเทียบชื่อบริษัท
def compare_company_names(actual_names, expected_name):
    # matches = [name for name in actual_names if expected_name.lower()
    #            in name.lower()]
    if expected_name.lower() in actual_names.lower():
        return True
    else:
        return False


def search_company_name(url):

    match = re.search(r'https?://', url)
    if match:
        domain = url.split(match.group(0))[1]
    else:
        domain = url
        url = 'https://'+url

    actual_names = ''
    cert_info = get_ssl_certificate_info(domain)

    if cert_info:
        for key, value in cert_info.items():
            if isinstance(value, list) and all(isinstance(item, tuple) for item in value):
                print(f"  {key}:")
                for item in value:
                    print(f"    {item}")
            else:
                if key == 'subject':
                    # print(f"  {key}:")
                    for items in value:
                        # print(f"    {items}")
                        if isinstance(items, tuple):
                            for i in items:
                                if "organizationName" in i:
                                    print(
                                        f"**SSL Certificate Information for {domain} => keyword : {i[1]}")
                                    actual_names = i[1]
                        else:
                            if "organizationName" in item:
                                print(
                                    f"**SSL Certificate Information for {domain} => keyword : {item}")
                                actual_names = item

        if actual_names == '':
            actual_names = get_company_names(url)
            if actual_names:
                print(
                    f">>URL meta tags information for {url} => keyword : {actual_names} ")
                return actual_names
            else:
                print(
                    f"-XxX- Could not retrieve SSL certificate and URL meta tags information for {url}")
                return actual_names
        else:
            return actual_names
    else:
        actual_names = get_company_names(url)
        if actual_names:
            print(
                f">>URL meta tags information for {url} : name : {actual_names} ")
            return actual_names
        else:
            print(
                f"-XxX- Could not retrieve SSL certificate and URL meta tags information for {url}")
            return actual_names


def separate_path_from_user(url):
    # Regular expression to match domain and path
    pattern = r'^(?:https?:\/\/)?(?:www\.)?[^\/]+(\/.*)?$'
    match = re.match(pattern, url)

    if match:
        path = match.group(1)
        # print(path)
        if path and path is not None:
            if '/' == path:
                lastindex = url.rfind('/')
                domain = url[0:lastindex]
            else:
                domain = url.replace(path, "")
            print(domain)
            return domain
        else:
            return url


if __name__ == "__main__":
    csvFile = pd.read_csv('sample_url2.csv')
    result_csv = list()
    for index, url in enumerate(csvFile.URL):
        print('###############################')
        comName = csvFile['Company name'][index]
        url = separate_path_from_user(url)
        keyword = search_company_name(url)
        result_dict = dict(company=comName, url=url, keyword=keyword)
        result_csv.append(result_dict)

    df = pd.DataFrame(result_csv)
    df.to_csv('checkCompany.csv', index=False)
    # print(result_csv)
