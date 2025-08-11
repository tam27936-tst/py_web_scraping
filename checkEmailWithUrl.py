import ssl
import socket
import re
import pandas
import math
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
        print(f"Error retrieving certificate for {hostname}:{port} - {e}")
        return None


def validate_email_with_certificate(url, email):

    match = re.search(r'https://', url)
    if match:
        domain = url.split('https://')[1]
    else:
        domain = url

    dns = ''
    validateEmail = False
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
                                if "commonName" in i:
                                    print(
                                        f"** SSL Certificate Information for {domain} => DNS : {i[1]}")
                                    dns = i[1]
                                    if '*.' in dns:
                                        dns = dns.replace('*.', '')
                                    elif 'www.' in dns:
                                        dns = dns.replace('www.', '')

                                    if dns in email:
                                        print(
                                            f"** The Email is valid according to {dns} => email : {email}")
                                        validateEmail = True
                                    else:
                                        print(
                                            f"** Invalid email format: the domain part ({dns}) of the email address  : {email}")
                        else:
                            if "commonName" in item:
                                print(
                                    f"** SSL Certificate Information for {domain} => DNS : {item}")
                                dns = i[1]
                                if '*.' in dns:
                                    dns = dns.replace('*.', '')
                                elif 'www.' in dns:
                                    dns = dns.replace('www.', '')

                                if dns in email:
                                    print(
                                        f"** The Email is valid according to {dns} => email : {email}")
                                    validateEmail = True
                                else:
                                    print(
                                        f"** Invalid email format: the domain part ({dns}) of the email address  : {email}")

    else:
        print(
            f"-XxX- Could not retrieve SSL certificate information for {url}")

    return validateEmail


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
    csvFile = pandas.read_csv('sample_url2.csv')
    # print(csvFile)
    df = csvFile[['URL', 'Email']]
    result_list = list()
    # print(df)
    for index, url in enumerate(df.URL):
        print(f'URL : {url}')
        url = separate_path_from_user(url)
        email = df.Email[index]
        print(f'Email : {email}')
        if url != '' and email != '' and isinstance(email, str):
            validateEmail = validate_email_with_certificate(url, email)
            result_dict = dict(url=url, email=email, validate=validateEmail)
            result_list.append(result_dict)
            print('**********************************')
        else:
            print('The Email is null')
            result_dict = dict(url=url, email=email, validate=False)
            result_list.append(result_dict)
            print('**********************************')

    df = pandas.DataFrame(result_list)
    df.to_csv('checkEmail.csv', index=False)
