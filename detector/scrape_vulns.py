import requests
from bs4 import BeautifulSoup
import json
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

OUTPUT_DIR = "vuln"

def scrape_vuln_detail(session, go_id, detail_url, retries=3):
    for attempt in range(retries):
        try:
            response = session.get(detail_url, timeout=30)
            if response.status_code == 429:
                time.sleep(10)
                continue
            if response.status_code != 200:
                return {"go_id": go_id, "url": detail_url, "error": f"HTTP {response.status_code}"}
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            aliases = []
            affects = []
            published = ""
            modified = ""
            description = ""
            references = []
            credits = []
            
            details = soup.find('div', class_='Vuln-details')
            if details:
                metadata = details.find('ul', class_='Vuln-detailsMetadata')
                if metadata:
                    for li in metadata.find_all('li'):
                        text = li.get_text(strip=True)
                        if text.startswith('CVE-') or text.startswith('GHSA-'):
                            aliases.append(text)
                        elif text.startswith('Published:'):
                            published = text.replace('Published:', '').strip()
                        elif text.startswith('Modified:'):
                            modified = text.replace('Modified:', '').strip()
                
                desc_elem = details.find('p')
                if desc_elem:
                    description = desc_elem.get_text(strip=True)
            
            entry = soup.find('div', class_='VulnEntry')
            if entry:
                packages_table = entry.find('ul', class_='VulnEntryPackages')
                if packages_table:
                    items = packages_table.find_all('li', class_='VulnEntryPackages-item')
                    for item in items[1:]:
                        path_elem = item.find('div', {'data-name': 'Path'})
                        go_ver_elem = item.find('div', {'data-name': 'Go Versions'})
                        symbols_elem = item.find('div', class_='VulnEntryPackages-symbols')
                        
                        path = path_elem.get_text(strip=True) if path_elem else ""
                        go_versions = go_ver_elem.get_text(strip=True) if go_ver_elem else ""
                        
                        symbols = []
                        if symbols_elem:
                            for a in symbols_elem.find_all('a'):
                                symbols.append(a.get_text(strip=True))
                        
                        if path:
                            affects.append({
                                "path": path,
                                "go_versions": go_versions,
                                "symbols": symbols
                            })
                
                aliases_list = entry.find('ul', class_='VulnEntry-aliases')
                if aliases_list:
                    new_aliases = [a.get_text(strip=True) for a in aliases_list.find_all('a')]
                    if new_aliases:
                        aliases = new_aliases
                
                ref_list = entry.find('ul', class_='VulnEntry-referenceList')
                if ref_list:
                    for li in ref_list.find_all('li'):
                        a = li.find('a')
                        if a and a.get('href'):
                            references.append(a.get('href'))
                
                credits_section = entry.find('h2', string='Credits')
                if credits_section:
                    credits_parent = credits_section.find_next_sibling('ul')
                    if credits_parent:
                        for li in credits_parent.find_all('li'):
                            credits.append(li.get_text(strip=True))
            
            return {
                "go_id": go_id,
                "url": detail_url,
                "aliases": aliases,
                "affects": affects,
                "published": published,
                "modified": modified,
                "description": description,
                "references": references,
                "credits": credits
            }
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(2)
                continue
            return {"go_id": go_id, "url": detail_url, "error": str(e)}
    
    return {"go_id": go_id, "url": detail_url, "error": "Max retries exceeded"}

def save_vuln(vuln):
    filename = os.path.join(OUTPUT_DIR, f"{vuln['go_id']}.json")
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(vuln, f, ensure_ascii=False, indent=2)

def get_existing_ids():
    if not os.path.exists(OUTPUT_DIR):
        return set()
    return {f.replace('.json', '') for f in os.listdir(OUTPUT_DIR) if f.endswith('.json')}

def scrape_all_vulns():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    
    url = "https://pkg.go.dev/vuln/list"
    for attempt in range(3):
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 429:
                print("Rate limited, waiting 30s...")
                time.sleep(30)
                continue
            break
        except:
            time.sleep(5)
    
    soup = BeautifulSoup(response.text, 'html.parser')
    vuln_list = soup.find_all('div', class_='VulnList-header')
    
    vuln_urls = []
    for vuln_header in vuln_list:
        title_elem = vuln_header.find('h2', class_='VulnList-title')
        if not title_elem:
            continue
        link = title_elem.find('a')
        if not link:
            continue
        go_id = link.get_text(strip=True)
        detail_url = "https://pkg.go.dev" + str(link.get('href') or '')
        vuln_urls.append((go_id, detail_url))
    
    existing_ids = get_existing_ids()
    to_scrape = [(go_id, url) for go_id, url in vuln_urls if go_id not in existing_ids]
    
    print(f"Total: {len(vuln_urls)}, Already scraped: {len(existing_ids)}, To scrape: {len(to_scrape)}")
    
    if not to_scrape:
        print("All vulnerabilities already scraped!")
        return
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(scrape_vuln_detail, session, go_id, url): (go_id, url) for go_id, url in to_scrape}
        
        completed = 0
        for future in as_completed(futures):
            completed += 1
            result = future.result()
            save_vuln(result)
            if completed % 50 == 0:
                print(f"Progress: {completed}/{len(to_scrape)}")
            time.sleep(0.5)
    
    print(f"Done! Scraped {len(to_scrape)} new vulnerabilities")

if __name__ == "__main__":
    scrape_all_vulns()
