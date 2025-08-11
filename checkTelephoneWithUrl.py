from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import requests
import requests
import pandas
import re
from bs4 import BeautifulSoup


def findTelephoneWithUrl(base_url):
    # base_url = "https://www.bigcamera.co.th/"  # Ensure absolute URLs for parsing
    extracted_paths = set()  # Use a set to avoid duplicate paths
    try:
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

            if '/contact' in path:
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
                            # print()
                            match_tel1 = re.search(
                                r'\(\+66\)\d{4}-\d{4}-\d{1}$', value)
                            match_tel2 = re.search(
                                r'0\d{2,3}[-\s]?\d{6,7}$', value)
                            match_tel3 = re.search(
                                r'((\+66|0)(\d{1,2}[-\s]?\d{3}[-\s]?\d{3,4}))|((\+๖๖|๐)([๐-๙]{1,2}[-\s]?[๐-๙]{3}[-\s]?[๐-๙]{3,4}))', value)
                            if match_tel1 or match_tel2 or match_tel3:
                                print(value)
    except requests.exceptions.ConnectionError as e:
        print(e)


def checkTelephoneWithUrl(base_url, tel):
    check = False
    try:
        match = re.search(r'https?://', base_url)
        # print(match)
        if match is None:
            base_url = 'http://'+base_url

        url = requests.get(base_url)
        soup = BeautifulSoup(url.content, 'html.parser')
        child_soup = soup.find_all()
        for i in child_soup:
            for line in i.contents:
                value = line.text.strip()
                # print(line.__class__.__name__)
                if value and line.__class__.__name__ == 'NavigableString':
                    # print()
                    match_tel1 = re.search(
                        r'\(\+66\)\d{4}-\d{4}-\d{1}$', value)
                    match_tel2 = re.search(
                        r'0\d{2,3}[-\s]?\d{6,7}$', value)
                    match_tel3 = re.search(
                        r'((\+66|0)(\d{1,2}[-\s]?\d{3}[-\s]?\d{3,4}))|((\+๖๖|๐)([๐-๙]{1,2}[-\s]?[๐-๙]{3}[-\s]?[๐-๙]{3,4}))', value)
                    if match_tel1 or match_tel2 or match_tel3:
                        findTel = match_tel3.group(0).strip()
                        findTel = findTel.replace('-', '')
                        findTel = findTel.replace(' ', '')
                        findTel = findTel.replace('+66', '0')
                        print(f'detect with utl : {findTel}')
                        if findTel.strip() == tel.strip():
                            check = True
        print(f'validate tel : {check}')
        return check
    except requests.exceptions.ConnectionError as e:
        print(e)
        return check


if __name__ == "__main__":

    csvFile = pandas.read_csv('sample_url2.csv')
    # print(csvFile)
    df = csvFile[['URL', 'Tel']]
    result_list = list()
    # print(df)
    for index, url in enumerate(df.URL):
        print(f'URL : {url}')
        tel = df.Tel[index]
        tel = tel.replace('-', '')
        print(f'Tel : {tel}')
        if url != '' and tel != '' and isinstance(tel, str):
            validateTel = checkTelephoneWithUrl(url, tel)
            result_dict = dict(url=url, telephone=tel, validate=validateTel)
            result_list.append(result_dict)
            print('**********************************')
        else:
            print('The Tel is null')
            result_dict = dict(url=url, telephone=tel, validate=False)
            result_list.append(result_dict)
            print('**********************************')

    df = pandas.DataFrame(result_list)
    df.to_csv('checkTelephone.csv', index=False)
