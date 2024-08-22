# from datetime import datetime as dt
# import requests
# from bs4 import BeautifulSoup
# import asyncio
# import aiohttp
# import re
# from urllib.parse import quote
# import csv
# async def fetch(session, url):
#     try:
#         async with session.get(url) as response:
#             if response.status == 200:
#                 return await response.text()
#             else:
#                 print("Error received !!! ")
#                 return None
#     except aiohttp.ClientError as e:
#         print(f"Client error: {e}")
#         return None

# async def main():
#     date = dt.now().strftime("%m/%d/%Y")

#     # Extract month, day, and year from the date string
#     month, day, year = date.split('/')

#     # Format the individual components for the URL
#     formatted_month = quote(month)
#     formatted_day = quote(day)
#     formatted_year = year
#     url = f'https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&pub_start_date={formatted_month}%2F{formatted_day}%2F{formatted_year}&pub_end_date={formatted_month}%2F{formatted_day}%2F{formatted_year}'
#     headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}

#     csv_file = 'cve_data.csv'
#     fieldnames = ['Product Name', 'Description', 'Severity level', 'Published Date', 'Unique ID']

#     # Check if the file exists, if not, write the header row
#     try:
#         with open(csv_file, 'r') as file:
#             reader = csv.DictReader(file)
#             cve_ids_in_file = [row['Unique ID'] for row in reader]
#     except FileNotFoundError:
#         with open(csv_file, 'w', newline='') as file:
#             writer = csv.DictWriter(file, fieldnames=fieldnames)
#             writer.writeheader()
#             cve_ids_in_file = []

#     async with aiohttp.ClientSession() as session:
#         # Fetch the main page
#         main_page_html = await fetch(session, url)
#         if main_page_html:
#             soup = BeautifulSoup(main_page_html, 'html.parser')

#             cve_elements = soup.find_all('a', href=re.compile(r'/vuln/detail/CVE-\d{4}-\d+'))
#             cve_ids = [cve.get_text(strip=True) for cve in cve_elements]
            
#             for cve_id in cve_ids:
#                 print("="*100)

#                 url1 = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

#                 cve_detail_html = await fetch(session, url1)
#                 if cve_detail_html:
#                     soup1 = BeautifulSoup(cve_detail_html, 'html.parser')

#                     # Extracting description,severity, publish date, source
#                     try:
                        
#                         source_element = soup1.find('span', {'data-testid': 'vuln-current-description-source'})
#                         source = source_element.get_text(strip=True)
#                         # print("Product Name:",source)

#                         description_element = soup1.find('p', {'data-testid': 'vuln-description'})
#                         description = description_element.get_text(strip=True)
#                         # print("Description:", description)
                        
#                         severity_element = soup1.find('a', {'data-testid': 'vuln-cvss3-cna-panel-score'})
#                         severity  = severity_element.text.strip()
#                         # print("Severity level:",severity)
                        
#                         publish_element = soup1.find('span', {'data-testid': 'vuln-published-on'})
#                         published = publish_element.get_text(strip=True)
#                         # print("Published Date:",published)
                        
#                         print("Unique ID:", cve_id)
                    
#                         if cve_id not in cve_ids_in_file:
#                             with open(csv_file, 'a', newline='') as file:
#                                 writer = csv.DictWriter(file, fieldnames=fieldnames)
#                                 writer.writerow({
#                                     'Product Name': source,
#                                     'Description': description,
#                                     'Severity level': severity,
#                                     'Published Date': published,
#                                     'Unique ID': cve_id
#                                 })
#                             print(f"New CVE added to CSV: {cve_id}")
#                         else:
#                             print(f"CVE already exists in CSV: {cve_id}")
#                     except AttributeError as e:
#                         print("Error extracting description:", e)
#                 print("\n")  # Add a newline for better readability between CVEs

# # Run the main function
# asyncio.run(main())

from datetime import datetime as dt
import asyncio
import aiohttp
import re
from bs4 import BeautifulSoup
from urllib.parse import quote
import csv

async def fetch(session, url):
    try:
        async with session.get(url) as response:
            if response.status == 200:
                return await response.text()
            else:
                print("Error received !!! ")
                return None
    except aiohttp.ClientError as e:
        print(f"Client error: {e}")
        return None

async def main():
    date = dt.now().strftime("%m/%d/%Y")
    month, day, year = date.split('/')
    formatted_month = quote(month)
    formatted_day = quote(day)
    formatted_year = year
    url = f'https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&pub_start_date={formatted_month}%2F{formatted_day}%2F{formatted_year}&pub_end_date={formatted_month}%2F{formatted_day}%2F{formatted_year}'
    
    csv_file = 'cve_data.csv'
    fieldnames = ['Product Name', 'Description', 'Severity level', 'Published Date', 'Unique ID']

    # Check if the file exists, if not, write the header row
    cve_ids_in_file = set()
    try:
        with open(csv_file, 'r') as file:
            reader = csv.DictReader(file)
            cve_ids_in_file = {row['Unique ID'] for row in reader}
    except FileNotFoundError:
        with open(csv_file, 'w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            cve_ids_in_file = set()

    async with aiohttp.ClientSession() as session:
        # Fetch the main page
        main_page_html = await fetch(session, url)
        if main_page_html:
            soup = BeautifulSoup(main_page_html, 'html.parser')

            cve_elements = soup.find_all('a', href=re.compile(r'/vuln/detail/CVE-\d{4}-\d+'))
            
            cve_ids = [cve.get_text(strip=True) for cve in cve_elements]

            first_10_cve_ids = cve_ids[:10]

            for cve_id in first_10_cve_ids:

                if cve_id in cve_ids_in_file:
                    continue

                url1 = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                cve_detail_html = await fetch(session, url1)

                if cve_detail_html:
                    soup1 = BeautifulSoup(cve_detail_html, 'html.parser')
                    # Extracting description, severity, publish date, source
                    try:
                        source_element = soup1.find('span', {'data-testid': 'vuln-current-description-source'})
                        source = source_element.get_text(strip=True)

                        description_element = soup1.find('p', {'data-testid': 'vuln-description'})
                        description = description_element.get_text(strip=True)

                        severity_element = soup1.find('a', {'data-testid': 'vuln-cvss3-cna-panel-score'})
                        severity = severity_element.text.strip()

                        publish_element = soup1.find('span', {'data-testid': 'vuln-published-on'})
                        published = publish_element.get_text(strip=True)
                        # Write to CSV
                        with open(csv_file, 'a', newline='') as file:
                            writer = csv.DictWriter(file, fieldnames=fieldnames)
                            writer.writerow({
                                    'Unique ID': cve_id,
                                    'Product Name': source,
                                    'Description': description,
                                    'Severity level': severity,
                                    'Published Date': published
                            })
                    except AttributeError as e:
                        print("Error extracting description:", e)

asyncio.run(main())
