from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import requests
import requests
import pandas
import re
from bs4 import BeautifulSoup


def checkTermOfUse(base_url):
    # base_url = "https://www.bigcamera.co.th/"  # Ensure absolute URLs for parsing
    extracted_paths = set()  # Use a set to avoid duplicate paths

    try:
        match = re.search(r'https?://', base_url)
        # print(match)
        if match is None:
            base_url = 'https://'+base_url

        url = requests.get(base_url)
        soup = BeautifulSoup(url.content, 'html.parser')
        all_links = []
        for link in soup.find_all('a', href=True):
            #    print(link)
            all_links.append(link['href'])
        # print(all_links)
        for link_url in all_links:
            # Resolve relative URLs to absolute URLs
            absolute_url = urljoin(base_url, link_url)
            parsed_url = urlparse(absolute_url)
            if parsed_url.path:
                extracted_paths.add(parsed_url.path)

        for path in extracted_paths:
            # print(path)
            if '/terms-of-use' in path or '/terms-and-conditions' in path or '/terms-condition' in path:
                print(f"Detected contact paths: {base_url}{path}")
                contactPath = f"{base_url}{path}"
                # print(contactPath)
                url = requests.get(contactPath)
                soup = BeautifulSoup(url.content, 'html.parser')
                child_soup = soup.find_all()
                for i in child_soup:
                    for line in i.contents:
                        value = line.text.strip()
                        # print(line.__class__.__name__)
                        if value and line.__class__.__name__ == 'NavigableString':
                            # print(value)
                            if "ผู้ใช้บริการตกลงที่จะไม่คัดลอก ดัดแปลง" in value:
                                print(value)
                            elif "ทำซ้ำ" in value:
                                print(value)
                            elif "ดัดแปลง" in value:
                                print(value)
                            elif "ลอกเลียน" in value:
                                print(value)
                            elif "คัดลอก" in value:
                                print(value)
                            elif "เก็บข้อมูล" in value:
                                print(value)
                            elif "ดึงข้อมูล" in value:
                                print(value)
                            elif "ผลิตซ้ำ" in value:
                                print(value)
                            elif "ทำสำเนา" in value:
                                print(value)
    except requests.exceptions.ConnectionError as e:
        print(e)


def separate_path_from_user(url):

    # Regular expression to match domain and path
    pattern = r'^(?:https?:\/\/)?(?:www\.)?[^\/]+(\/.*)?$'
    match = re.match(pattern, url)

    if match:
        path = match.group(1)
        print(path)
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
    csvFile = pandas.read_csv('sample_url2.csv')
    # print(csvFile)
    for url in csvFile['URL']:
        print('****************')
        print(f"input url : {url}")
        domain = separate_path_from_user(url)
        print(f"detect domain : {domain}")
        checkTermOfUse(domain)
