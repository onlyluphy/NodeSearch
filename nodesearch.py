import sys
import requests
import re
from termcolor import colored
import json
from pyExploitDb import PyExploitDb
from bs4 import BeautifulSoup
import subprocess
import os
from time import sleep

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_menu():
    clear_screen()
    print(colored("CVE and Exploit Searcher - @3liot & NodeSec \n", "magenta", attrs=["bold"]))
    
    menu_options = [
        "Classic Search",
        "Advanced Search", 
        "Documentation",
        "Exit"
    ]
    
    descriptions = [
        "Standard CVE search by component and version",
        "Advanced search with SearchSploit and Exploit-DB", 
        "Documentation of tools used",
        "Exit the program"
    ]
    
    print(colored("═" * 70, "cyan"))
    print(colored("                         NODESEARCH    ", "cyan", attrs=["bold"]))
    print(colored("═" * 70, "cyan"))
    
    for i, (option, desc) in enumerate(zip(menu_options, descriptions)):
        print(colored(f"\n[{i+1}] {option}", "green", attrs=["bold"]))
        print(colored(f"    → {desc}", "white"))
    
    print(colored("\n" + "═" * 70, "cyan"))

def get_menu_selection():
    while True:
        display_menu()
        try:
            choice = input(colored("\n Select an option (1-4): ", "yellow", attrs=["bold"]))
            choice = int(choice)
            if 1 <= choice <= 4:
                return choice - 1
            else:
                print(colored(" Invalid choice! Please enter a number between 1 and 4.", "red"))
                input(colored("Press Enter to continue...", "cyan"))
        except ValueError:
            print(colored(" Please enter a valid number!", "red"))
            input(colored("Press Enter to continue...", "cyan"))
        except KeyboardInterrupt:
            return 3 

def find_cpes(component, version):
    base_url = "https://nvd.nist.gov/products/cpe/search/results"
    params = {
        "namingFormat": "2.3",
        "keyword": f"{component} {version}"
    }
    response = requests.get(base_url, params=params)
    content = response.text
    cpe_matches = re.findall(r'cpe:(.*?)<', content)
    return cpe_matches

def synk_db(cve_id):
    try:
        res = requests.get(f"https://security.snyk.io/vuln/?search={cve_id}")
        a_tag_pattern = r'data-snyk-test="vuln table title".*>([^"]+)<!----><!---->'
        a_tag_matches = re.findall(a_tag_pattern, res.text)
        if a_tag_matches:
            snyk_short_name = a_tag_matches[0].strip()
            return snyk_short_name
        return None
    except:
        return None

def search_exploit(cve_id):
    try:
        output = subprocess.check_output(['searchsploit', cve_id], stderr=subprocess.STDOUT, universal_newlines=True)
        if output.strip():
            return output
        else:
            return None
    except subprocess.CalledProcessError:
        return None
    except FileNotFoundError:
        return "SearchSploit not installed"

def search_exploitdb_api(query):
    try:
        pEdb = PyExploitDb()
        results = pEdb.searchCVE(query)
        return results
    except Exception as e:
        print(colored(f"Exploit-DB API Error: {e}", "red"))
        return None

def fetch_cve_details(cpe_string):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    url = f"{base_url}?cpeName=cpe:{cpe_string}"
    
    response = requests.get(url)
    if response.status_code != 200:
        print(colored(f"Error: Unable to retrieve CVE data for CPE: {cpe_string}", "yellow"))
        return []
    
    try:
        data = response.json()
    except json.JSONDecodeError:
        print(colored(f"JSON decoding error for CPE: {cpe_string}", "red"))
        return []

    all_cve_details = []
    for cve_item in data["vulnerabilities"]:
        cve_id = cve_item["cve"]["id"]
        description_text = cve_item["cve"]["descriptions"][0]["value"]
        severity = "Not Available"
        
        if "cvssMetricV2" in cve_item["cve"]["metrics"]:
            severity = cve_item["cve"]["metrics"]["cvssMetricV2"][0]["baseSeverity"]
        elif "cvssMetricV31" in cve_item["cve"]["metrics"]:
            severity = cve_item["cve"]["metrics"]["cvssMetricV31"][0]["baseSeverity"]
            
        snyk_short_name = synk_db(cve_id)
        
        weaknesses = []
        if "weaknesses" in cve_item["cve"]:
            for problem_type in cve_item["cve"]["weaknesses"]:
                for description in problem_type["description"]:
                    weaknesses.append(description["value"])

        all_cve_details.append({
            "CVE ID": cve_id,
            "Short Name": snyk_short_name,
            "Description": description_text,
            "Weaknesses": ", ".join(weaknesses) if weaknesses else "NO CWE",
            "severity": severity
        })
    
    return all_cve_details

def fetch_github_urls(cve_id):
    api_url = f"https://poc-in-github.motikan2010.net/api/v1/?cve_id={cve_id}"
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            data = response.json()
            if "pocs" in data and data["pocs"]:
                github_urls = [poc["html_url"] for poc in data["pocs"]]
                return github_urls
    except:
        pass
    return []

def search_and_extract_download_links(product_name):
    search_url = f"https://packetstormsecurity.com/search/?q={product_name}"
    try:
        response = requests.get(search_url)
        download_links = []
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            results = soup.find_all('a', href=True)
            for result in results:
                href = result['href']
                if '/files/download/' in href and href.endswith('.txt'):
                    download_links.append(f"https://packetstormsecurity.com{href}")
        
        return download_links
    except:
        return []

def search_marc_info(search_term):
    url = f"https://marc.info/?l=full-disclosure&s={search_term}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            if "No hits found for" in soup.get_text():
                return None
            else:
                pre_tag = soup.find('pre')
                if pre_tag:
                    post_links = pre_tag.find_all('a', string=lambda text: text and "full-disc" not in text)
                    if post_links:
                        results = []
                        for link in post_links:
                            name = link.get_text(strip=True)
                            link_url = "https://marc.info" + link['href']
                            results.append({"Name": name, "Link": link_url})
                        return results
    except:
        pass
    return None

def classic_search():
    clear_screen()
    print(colored("═" * 50, "green"))
    print(colored("            CLASSIC SEARCH", "green", attrs=["bold"]))
    print(colored("═" * 50, "green"))
    
    component = input(colored("\n Service name: ", "magenta", attrs=["bold"]))
    version = input(colored(" Version: ", "magenta", attrs=["bold"]))
    print(colored(f"\n Searching for {component} {version}...", "cyan"))
    
    cpe_strings = find_cpes(component, version)
    
    if cpe_strings:
        print(colored("\n=== COMMON PLATFORM ENUMERATION ===", "green", attrs=["bold"]))
        for cpe_string in cpe_strings:
            print(colored(f"  {cpe_string}", "white"))
        
        for cpe_string in cpe_strings:
            results = fetch_cve_details(cpe_string)
            if results:
                for result in results:
                    cve_id = result["CVE ID"]
                    print("_" * 88)
                    
                    if result["Short Name"]:
                        print(colored(f"\nCVE DETAILS > {cve_id} [{result['Short Name']}]", "magenta", attrs=["bold"]))
                    else:
                        print(colored(f"\nCVE DETAILS > {cve_id}", "magenta", attrs=["bold"]))
                    
                    if result["Weaknesses"]:
                        print(colored(f"Weakness Enumeration: {result['Weaknesses']}", "white"))
                    
                    severity = result['severity']
                    if severity in ["CRITICAL", "HIGH"]:
                        print("SEVERITY >> " + colored(f"{severity}", "red", attrs=["bold"]))
                    elif severity == "MEDIUM":
                        print("SEVERITY >> " + colored(f"{severity}", "yellow", attrs=["bold"]))
                    elif severity == "LOW":
                        print("SEVERITY >> " + colored(f"{severity}", "green", attrs=["bold"]))
                    
                    print(colored(f"{result['Description']}", "yellow"))
                    
                    github_urls = fetch_github_urls(cve_id)
                    if github_urls:
                        print(colored("\n[GitHub] Public Exploit/POC >", "red"))
                        for url in github_urls:
                            print(colored(f"  {url}", "blue"))
                    else:
                        print(colored("No public exploit/POC found on GitHub", "green"))
                    
                    exploit_result = search_exploit(cve_id)
                    if exploit_result and "SearchSploit not installed" not in exploit_result:
                        print(colored(f"\n[Exploit-DB] Public Exploit >", "red"))
                        print(colored(f"  https://www.exploit-db.com/search?cve={cve_id}", "blue"))
                    else:
                        print(colored("No public exploit found on Exploit-DB", "green"))
    else:
        print(colored("No CPE found for this component and version.", "red"))
    
    download_links = search_and_extract_download_links(component)
    if download_links:
        print(colored("\n=== POSSIBLE EXPLOITS [Packet Storm Security] ===", "magenta", attrs=["underline"]))
        for link in download_links:
            print(colored(link, "blue"))
    else:
        print(colored("No download links found on Packet Storm Security.", "red"))
    
    search_term_marc = f"{component} {version}"
    print(colored(f"\nSearching Marc.Info with '{search_term_marc}'...", "cyan"))
    marc_results = search_marc_info(search_term_marc)
    if marc_results:
        print(colored("\n=== POSSIBLE EXPLOITS [Marc.Info] ===", "magenta", attrs=["underline"]))
        for result in marc_results:
            print(colored(f"\nName: {result['Name']}", "white"))
            print(colored(f"Link: {result['Link']}", "blue"))
    
    input(colored("\nPress Enter to continue...", "cyan"))

def advanced_search():
    clear_screen()
    print(colored("═" * 50, "green"))
    print(colored("            ADVANCED SEARCH", "green", attrs=["bold"]))
    print(colored("═" * 50, "green"))
    
    print(colored("\n[1]  Search by CVE ID", "cyan"))
    print(colored("[2]  Search by services", "cyan"))
    
    search_type = input(colored("\n Your choice (1/2): ", "magenta", attrs=["bold"]))
    
    if search_type == "1":
        cve_id = input(colored("\n CVE ID (ex: CVE-2021-44228): ", "magenta", attrs=["bold"]))
        
        print(colored(f"\n═══ ADVANCED SEARCH FOR {cve_id} ═══", "cyan", attrs=["bold"]))
        
        print(colored("\n[SearchSploit Results]", "yellow", attrs=["bold"]))
        exploit_output = search_exploit(cve_id)
        if exploit_output and "SearchSploit not installed" not in exploit_output:
            print(colored(exploit_output, "white"))
        else:
            print(colored("No SearchSploit results or tool not installed", "red"))
    
        print(colored("\n[Exploit-DB API Results]", "yellow", attrs=["bold"]))
        api_results = search_exploitdb_api(cve_id)
        if api_results:
            for result in api_results:
                print(colored(f"ID: {result.get('id', 'N/A')}", "green"))
                print(colored(f"Title: {result.get('description', 'N/A')}", "white"))
                print(colored(f"Platform: {result.get('platform', 'N/A')}", "cyan"))
                print(colored(f"Type: {result.get('type', 'N/A')}", "cyan"))
                print(colored(f"Link: https://www.exploit-db.com/exploits/{result.get('id', '')}", "blue"))
                print("-" * 60)
        else:
            print(colored("No results found in Exploit-DB API", "red"))
            
        github_urls = fetch_github_urls(cve_id)
        if github_urls:
            print(colored(f"\n[GitHub POC/Exploits for {cve_id}]", "yellow", attrs=["bold"]))
            for url in github_urls:
                print(colored(f"  {url}", "blue"))
        else:
            print(colored(f"No GitHub POC found for {cve_id}", "red"))
            
    elif search_type == "2":
        keyword = input(colored("> Search services: ", "magenta"))
        
        print(colored(f"\n=== ADVANCED SEARCH FOR '{keyword}' ===", "cyan", attrs=["bold"]))
        
        print(colored("\n[SearchSploit Results]", "yellow", attrs=["bold"]))
        try:
            output = subprocess.check_output(['searchsploit', keyword], stderr=subprocess.STDOUT, universal_newlines=True)
            if output.strip():
                print(colored(output, "white"))
            else:
                print(colored("No SearchSploit results", "red"))
        except:
            print(colored("SearchSploit not available or error", "red"))
        
        print(colored(f"\n[Exploit-DB Search URL]", "yellow", attrs=["bold"]))
        print(colored(f"https://www.exploit-db.com/search?q={keyword}", "blue"))
        
    input(colored("\nPress Enter to continue...", "cyan"))

def show_documentation():
    clear_screen()
    print(colored("═" * 50, "green"))
    print(colored("            DOCUMENTATION", "green", attrs=["bold"]))
    print(colored("═" * 50, "green"))
    
    docs = {
        "SearchSploit": {
            "description": "Command-line tool to search the Exploit-DB database",
            "installation": "apt-get install exploitdb",
            "usage": "searchsploit <search_term>",
            "website": "https://www.exploit-db.com/"
        },
        "PyExploitDb": {
            "description": "Python library to access the Exploit-DB API",
            "installation": "pip install pyExploitDb",
            "usage": "from pyExploitDb import PyExploitDb",
            "github": "https://github.com/GitHackTools/PyExploitDb"
        },
        "NVD (National Vulnerability Database)": {
            "description": "US vulnerability database",
            "api": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "website": "https://nvd.nist.gov/",
            "note": "Used to retrieve CVE and CPE details"
        },
        "Snyk Security Database": {
            "description": "Vulnerability database with short names",
            "website": "https://security.snyk.io/",
            "usage": "Automatic search for CVE short names"
        },
        "GitHub POC Database": {
            "description": "Collection of proof-of-concepts on GitHub",
            "api": "https://poc-in-github.motikan2010.net/api/v1/",
            "note": "Automatic search for POCs for CVEs"
        },
        "Packet Storm Security": {
            "description": "Security website with exploits and advisories",
            "website": "https://packetstormsecurity.com/",
            "note": "Search for exploits by keyword"
        },
        "Marc.info Full Disclosure": {
            "description": "Archive of the full-disclosure mailing list",
            "website": "https://marc.info/?l=full-disclosure",
            "note": "Search in security discussion archives"
        }
    }
    
    for tool, info in docs.items():
        print(colored(f"▶ {tool}", "cyan", attrs=["bold"]))
        for key, value in info.items():
            if key == "description":
                print(colored(f"   Description: {value}", "white"))
            elif key == "installation":
                print(colored(f"   Installation: {value}", "green"))
            elif key == "usage":
                print(colored(f"   Usage: {value}", "yellow"))
            elif key == "website":
                print(colored(f"   Website: {value}", "blue"))
            elif key == "api":
                print(colored(f"   API: {value}", "blue"))
            elif key == "github":
                print(colored(f"   GitHub: {value}", "blue"))
            elif key == "note":
                print(colored(f"   Note: {value}", "magenta"))
        print()
    
    print(colored("\nREQUIRED PYTHON DEPENDENCIES:", "red", attrs=["bold"]))
    dependencies = [
        "requests", "termcolor", "pyExploitDb", "beautifulsoup4", 
        "subprocess", "json", "re"
    ]
    
    for dep in dependencies:
        print(colored(f"{dep}", "white"))
    
    print(colored("\nINSTALLATION:", "red", attrs=["bold"]))
    print(colored("pip install requests termcolor pyExploitDb beautifulsoup4", "green"))
    
    input(colored("\nPress Enter to continue...", "cyan"))

def main():
    try:
        while True:
            selection = get_menu_selection()
            
            if selection == 0:  
                classic_search()
            elif selection == 1:  
                advanced_search()
            elif selection == 2:  
                show_documentation()
            elif selection == 3:  
                clear_screen()
                print(colored("Bye bye ", "magenta", attrs=["bold"]))
                sys.exit(0)
            
    except KeyboardInterrupt:
        clear_screen()
        print(colored("\nProgram interrupted by user.", "red"))
        sys.exit(0)
    except Exception as e:
        print(colored(f"Error: {e}", "red"))
        input(colored("Press Enter to continue...", "cyan"))

if __name__ == "__main__":
    main()
