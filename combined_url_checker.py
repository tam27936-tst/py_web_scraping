import ssl
import socket
import requests
import re
import pandas as pd
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import sys
from io import StringIO
import logging
from typing import Tuple, Optional, Dict, Any
from dataclasses import dataclass
import time


@dataclass
class CheckResult:
    """Data class to hold check results"""
    url: str
    company_name: str
    email: str
    telephone: str
    url_accessible: bool
    company_keyword: str
    terms_found: bool
    terms_text: str
    email_valid: bool
    telephone_found: bool


class URLChecker:
    """Main class for URL checking functionality"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Thai keywords for terms of use
        self.terms_keywords = [
            "ผู้ใช้บริการตกลงที่จะไม่คัดลอก ดัดแปลง", "ทำซ้ำ", "ดัดแปลง", 
            "ลอกเลียน", "คัดลอก", "เก็บข้อมูล", "ดึงข้อมูล", "ผลิตซ้ำ", "ทำสำเนา"
        ]
        
        # Phone patterns
        self.phone_patterns = [
            r'\(\+66\)\d{4}-\d{4}-\d{1}$',
            r'0\d{2,3}[-\s]?\d{6,7}$',
            r'((\+66|0)(\d{1,2}[-\s]?\d{3}[-\s]?\d{3,4}))|((\+๖๖|๐)([๐-๙]{1,2}[-\s]?[๐-๙]{3}[-\s]?[๐-๙]{3,4}))'
        ]

    def get_ssl_certificate_info(self, hostname: str, port: int = 443) -> Optional[dict]:
        """Get SSL certificate information for a hostname"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.getpeercert()
        except (socket.error, ssl.SSLError, ConnectionRefusedError, socket.timeout):
            return None

    def clean_url(self, url: str) -> str:
        """Clean and normalize URL"""
        if not url:
            return ""
            
        # Remove path from URL
        pattern = r'^(?:https?:\/\/)?(?:www\.)?[^\/]+(\/.*)?$'
        match = re.match(pattern, url)
        
        if match:
            path = match.group(1)
            if path and path != '/':
                return url.replace(path, "")
        
        return url

    def check_url_accessibility(self, url: str) -> Tuple[bool, str, Optional[requests.Response]]:
        """Check if URL is accessible and return response"""
        try:
            if not re.match(r'https?://', url):
                url = 'https://' + url
                
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                print(f"✓ URL accessible: {url}")
                return True, url, response
            else:
                print(f"✗ URL returned status {response.status_code}: {url}")
                return False, url, None
                
        except requests.RequestException as e:
            print(f"✗ URL connection failed: {url} - {str(e)}")
            return False, url, None

    def extract_domain_from_url(self, url: str) -> str:
        """Extract domain from URL"""
        match = re.search(r'https?://', url)
        if match:
            return url.split(match.group(0))[1].split('/')[0]
        return url.split('/')[0]

    def get_company_name(self, url: str, response_text: Optional[str] = None) -> str:
        """Get company name from SSL certificate or meta tags"""
        domain = self.extract_domain_from_url(url)
        company_name = ""
        
        # Try SSL certificate first
        cert_info = self.get_ssl_certificate_info(domain)
        if cert_info:
            for key, value in cert_info.items():
                if key == 'subject' and isinstance(value, (list, tuple)):
                    for item in value:
                        if isinstance(item, tuple):
                            for field in item:
                                if isinstance(field, tuple) and len(field) == 2 and field[0] == 'organizationName':
                                    company_name = field[1]
                                    print(f"**SSL Certificate Information for {domain} => keyword : {company_name}")
                                    return company_name

        # Fallback to meta tags if SSL doesn't have org info
        if not company_name and response_text:
            try:
                soup = BeautifulSoup(response_text, "html.parser")
                meta_tags = soup.find_all("meta")
                
                for tag in meta_tags:
                    if tag.get("property") == "og:site_name" and tag.get("content"):
                        company_name = tag.get("content")
                        print(f">>URL meta tags information for {url} => keyword : {company_name}")
                        return company_name
                    elif tag.get("name") == "author" and tag.get("content"):
                        company_name = tag.get("content")
                        print(f">>URL meta tags information for {url} => keyword : {company_name}")
                        return company_name
            except Exception as e:
                self.logger.error(f"Error parsing meta tags: {e}")

        if not company_name:
            print(f"-XxX- Could not retrieve SSL certificate and URL meta tags information for {url}")
            
        return company_name

    def validate_email_with_certificate(self, url: str, email: str) -> bool:
        """Validate email against SSL certificate domain"""
        if not email or not isinstance(email, str):
            return False
            
        domain = self.extract_domain_from_url(url)
        cert_info = self.get_ssl_certificate_info(domain)
        
        if not cert_info:
            print(f"-XxX- Could not retrieve SSL certificate information for {url}")
            return False

        try:
            for key, value in cert_info.items():
                if key == 'subject' and isinstance(value, (list, tuple)):
                    for item in value:
                        if isinstance(item, tuple):
                            for field in item:
                                if isinstance(field, tuple) and len(field) == 2 and field[0] == 'commonName':
                                    dns = field[1]
                                    print(f"** SSL Certificate Information for {domain} => DNS : {dns}")
                                    
                                    # Clean DNS
                                    if dns.startswith('*.'):
                                        dns = dns[2:]
                                    elif dns.startswith('www.'):
                                        dns = dns[4:]
                                    
                                    if dns in email:
                                        print(f"** The Email is valid according to {dns} => email : {email}")
                                        return True
                                    else:
                                        print(f"** Invalid email format: the domain part ({dns}) of the email address : {email}")
                                        
        except Exception as e:
            self.logger.error(f"Error validating email: {e}")
            
        return False

    def check_terms_of_use(self, base_url: str, initial_response: Optional[requests.Response] = None) -> Tuple[bool, str]:
        """Check for terms of use page and content"""
        try:
            if initial_response:
                soup = BeautifulSoup(initial_response.content, 'html.parser')
            else:
                response = self.session.get(base_url, timeout=self.timeout)
                soup = BeautifulSoup(response.content, 'html.parser')

            # Extract all links
            links = []
            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(base_url, link['href'])
                parsed_url = urlparse(absolute_url)
                if parsed_url.path:
                    links.append(parsed_url.path)

            # Look for terms of use pages
            terms_paths = [path for path in set(links) 
                          if any(term in path.lower() for term in 
                                ['/terms-of-use', '/terms-and-conditions', '/terms-condition',
                                    '/terms', '/tos', '/legal', '/policy', '/conditions',
                                    '/terms-of-service', '/user-agreement', '/user-terms',
                                    '/privacy-policy', '/privacy', '/กฎ', '/เงื่อนไข'])]

            for path in terms_paths:
                terms_url = urljoin(base_url, path)
                print(f"Detected terms path: {terms_url}")
                
                try:
                    terms_response = self.session.get(terms_url, timeout=self.timeout)
                    terms_soup = BeautifulSoup(terms_response.content, 'html.parser')
                    
                    # Remove script and style elements
                    for script in terms_soup(["script", "style"]):
                        script.extract()
                    
                    text_content = terms_soup.get_text()
                    
                    # Check for Thai keywords
                    found_texts = []
                    for keyword in self.terms_keywords:
                        if keyword in text_content:
                            # Find sentences containing the keyword
                            sentences = re.split(r'[.!?]', text_content)
                            for sentence in sentences:
                                if keyword in sentence:
                                    clean_sentence = ' '.join(sentence.strip().split())
                                    if clean_sentence:
                                        print(clean_sentence)
                                        found_texts.append(clean_sentence)
                                    break
                    
                    if found_texts:
                        return True, '; '.join(found_texts)
                        
                except requests.RequestException:
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error checking terms of use: {e}")
            
        return False, ""

    def check_telephone(self, base_url: str, target_tel: str, initial_response: Optional[requests.Response] = None) -> bool:
        """Check if telephone number exists on website"""
        if not target_tel or not isinstance(target_tel, str):
            print('The Tel is null')
            return False
            
        try:
            if initial_response:
                soup = BeautifulSoup(initial_response.content, 'html.parser')
            else:
                response = self.session.get(base_url, timeout=self.timeout)
                soup = BeautifulSoup(response.content, 'html.parser')

            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.extract()
                
            text_content = soup.get_text()
            
            # Clean target telephone
            clean_target = re.sub(r'[-\s\(\)]', '', target_tel.replace('+66', '0'))
            
            # Search for phone patterns
            for pattern in self.phone_patterns:
                matches = re.finditer(pattern, text_content)
                for match in matches:
                    found_tel = match.group(0).strip()
                    clean_found = re.sub(r'[-\s\(\)]', '', found_tel.replace('+66', '0'))
                    
                    print(f'detect with url : {clean_found}')
                    
                    if clean_found == clean_target:
                        print(f'validate tel : True')
                        return True
            
            print(f'validate tel : False')
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking telephone: {e}")
            print(f'validate tel : False')
            return False

    def process_single_url(self, row: Dict[str, Any], index: int) -> CheckResult:
        """Process a single URL with all checks"""
        print('#' * 31)
        print(f'Processing URL {index + 1}: {row.get("URL", "")}')
        
        # Clean URL
        original_url = row.get('URL', '')
        clean_url = self.clean_url(original_url)
        
        # Get other data
        company_name = row.get('Company name', '')
        email = row.get('Email', '')
        telephone = str(row.get('Tel', '')) if pd.notna(row.get('Tel', '')) else ''
        
        print(f'Company name: {company_name}')
        
        # Check URL accessibility
        url_accessible, final_url, response = self.check_url_accessibility(clean_url)
        
        if not url_accessible:
            print(f"URL not accessible: {clean_url}")
            return CheckResult(
                url=clean_url,
                company_name=company_name,
                email=email,
                telephone=telephone,
                url_accessible=False,
                company_keyword='',
                terms_found=False,
                terms_text='',
                email_valid=False,
                telephone_found=False
            )
        
        # Perform all checks using the single response
        print(f"URL accessible, performing checks...")
        
        # Get company keyword
        company_keyword = self.get_company_name(clean_url, response.text)
        
        # Check terms of use
        terms_found, terms_text = self.check_terms_of_use(final_url, response)
        
        # Validate email
        email_valid = False
        if email and isinstance(email, str):
            print(f'URL : {final_url}')
            print(f'Email : {email}')
            email_valid = self.validate_email_with_certificate(final_url, email)
            print('**' * 17)
        else:
            print('The Email is null')
            print('**' * 17)
        
        # Check telephone
        telephone_found = False
        if telephone:
            print(f'URL : {final_url}')
            telephone_clean = telephone.replace('-', '')
            print(f'Tel : {telephone_clean}')
            telephone_found = self.check_telephone(final_url, telephone_clean, response)
            print('**' * 17)
        else:
            print('The Tel is null')
            print('**' * 17)
        
        result = CheckResult(
            url=clean_url,
            company_name=company_name,
            email=email,
            telephone=telephone,
            url_accessible=True,
            company_keyword=company_keyword,
            terms_found=terms_found,
            terms_text=terms_text,
            email_valid=email_valid,
            telephone_found=telephone_found
        )
        
        print(f'Result: {result.__dict__}')
        print('=' * 50)
        
        return result


class Logger:
    """Custom logger to capture both console and file output"""
    def __init__(self):
        self.terminal = sys.stdout
        self.log = StringIO()

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.terminal.flush()

    def get_log(self):
        return self.log.getvalue()


def main():
    """Main execution function"""
    # Setup logging
    logger = Logger()
    sys.stdout = logger
    
    try:
        # Read CSV file
        print("Reading CSV file...")
        csv_file = pd.read_csv('sample_url2.csv')
        
        # Initialize checker
        checker = URLChecker(timeout=15)
        
        # Process each URL
        results = []
        total_urls = len(csv_file)
        
        start_time = time.time()
        
        for index, row in csv_file.iterrows():
            try:
                result = checker.process_single_url(row, index)
                results.append(result)
            except Exception as e:
                print(f"Error processing row {index}: {e}")
                # Add failed result
                results.append(CheckResult(
                    url=row.get('URL', ''),
                    company_name=row.get('Company name', ''),
                    email=row.get('Email', ''),
                    telephone=str(row.get('Tel', '')) if pd.notna(row.get('Tel', '')) else '',
                    url_accessible=False,
                    company_keyword='',
                    terms_found=False,
                    terms_text='',
                    email_valid=False,
                    telephone_found=False
                ))
        
        # Convert results to DataFrame
        df_results = pd.DataFrame([result.__dict__ for result in results])
        df_results.columns = [
            'URL', 'Company_Name', 'Email', 'Telephone', 'URL_Accessible',
            'Company_Keyword', 'Terms_Of_Use_Found', 'Terms_Of_Use_Text',
            'Email_Valid', 'Telephone_Found'
        ]
        
        # Save results
        df_results.to_csv('combined_check_results.csv', index=False)
        
        # Calculate statistics
        accessible_count = sum(r.url_accessible for r in results)
        terms_count = sum(r.terms_found for r in results)
        email_valid_count = sum(r.email_valid for r in results)
        telephone_found_count = sum(r.telephone_found for r in results)
        
        elapsed_time = time.time() - start_time
        
        print(f"\n{'='*60}")
        print(f"PROCESSING COMPLETE")
        print(f"{'='*60}")
        print(f"Total URLs processed: {total_urls}")
        print(f"Accessible URLs: {accessible_count} ({accessible_count/total_urls*100:.1f}%)")
        print(f"URLs with Terms of Use: {terms_count} ({terms_count/total_urls*100:.1f}%)")
        print(f"Valid emails: {email_valid_count} ({email_valid_count/total_urls*100:.1f}%)")
        print(f"Telephone numbers found: {telephone_found_count} ({telephone_found_count/total_urls*100:.1f}%)")
        print(f"Processing time: {elapsed_time:.2f} seconds")
        print(f"Average time per URL: {elapsed_time/total_urls:.2f} seconds")
        
    except FileNotFoundError:
        print("Error: sample_url2.csv file not found!")
    except Exception as e:
        print(f"Critical error: {e}")
    finally:
        # Save log to file
        try:
            with open('log.txt', 'w', encoding='utf-8') as f:
                f.write(logger.get_log())
        except Exception as e:
            print(f"Error saving log: {e}")
        
        # Restore stdout
        sys.stdout = sys.__stdout__
        
        print("Results saved to 'combined_check_results.csv'")
        print("Log saved to 'log.txt'")


if __name__ == "__main__":
    main()