import requests
from bs4 import BeautifulSoup

# ฟังก์ชันดึงชื่อบริษัทจากเว็บ


def get_company_names(url):
    response = requests.get(url)
    if response.status_code != 200:
        print("ไม่สามารถเข้าถึงเว็บได้")
        return []

    soup = BeautifulSoup(response.text, "html.parser")

    # ค้นหา meta tag ที่เกี่ยวข้อง
    meta_tags = soup.find_all("meta")

    for tag in meta_tags:
        if tag.get("property") == "og:site_name":  # ดึงจาก Open Graph
            return tag.get("content")
        elif tag.get("name") == "author":  # ดึงจาก meta author (บางเว็บใช้สำหรับบริษัท)
            return tag.get("content")

    return "ไม่พบชื่อบริษัทใน meta tags"


# ฟังก์ชันเปรียบเทียบชื่อบริษัท
def compare_company_names(actual_names, expected_name):
    matches = [name for name in actual_names if expected_name.lower()
               in name.lower()]
    return matches


# URL ของเว็บที่ต้องการดึงข้อมูล
url = "https://www.bol.co.th"  # เปลี่ยน URL ให้ตรงกับเว็บจริง

# ดึงชื่อบริษัทจากเว็บ
company_list = get_company_names(url)

# ชื่อที่คาดหวัง
expected_company_name = "Business Online"

# เปรียบเทียบชื่อบริษัท
matching_companies = compare_company_names(company_list, expected_company_name)

# แสดงผลลัพธ์
if matching_companies:
    print(f"บริษัทที่ตรงกับ '{expected_company_name}': {matching_companies}")
else:
    print(f"ไม่พบบริษัทที่ตรงกับ '{expected_company_name}'")
