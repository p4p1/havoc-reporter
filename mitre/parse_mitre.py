#!/usr/bin/env python
# -*- Coding: UTF-8 -*-
# Author: Jakob Friedl
# Created on: Mon, 30. Oct. 2023
# Description: Parses MITRE ATT&CK enterprise tactics, techniques and sub-techniques

from bs4 import BeautifulSoup
import requests
import re
import urllib3
import json
from urllib.parse import urljoin, urlparse
from collections import OrderedDict
from pprint import pprint

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = "https://attack.mitre.org/tactics/"
tactics = [
    "TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004",
    "TA0005", "TA0006", "TA0007", "TA0008", "TA0009", "TA0011",
    "TA0010", "TA0040"
]
mitre = []
outfile = "mitre.json"

def filter(lst):
    return [i for i in lst.contents if i != "\n"]

def fetch_mitre():
    # Tactics
    for tactic_id in tactics: 
        tactic_url = urljoin(url, tactic_id)
        
        r = requests.get(tactic_url, verify=False) 
        soup = BeautifulSoup(r.text, "html.parser")
        desc = soup.find_all(attrs={"class": "description-body"})[0]

        tactic_object = {
            "tactic": soup.html.h1.string.strip(),
            "id": tactic_id,
            "link": tactic_url,
            "description": desc.contents[1].get_text().strip(), 
            "long-description": desc.contents[2].get_text().strip(),
            "techniques": []
        }

        print("[*] Getting tactic information:", soup.html.h1.string.strip())

        techniques = soup.select("tr.technique:not(.sub)")
        subtechniques = soup.select("tr.sub.technique")

        # Techniques 
        for technique in techniques: 
            t = filter(technique) 
            
            t_url = t[0].contents[1].get("href")
     
            technique_url = urljoin(url, t_url)
            technique_name = t[1].contents[1].string.strip()
            technique_desc = t[2].get_text().strip()

            # Sub-techniques 
            sub_techniques = []
            for sub in subtechniques:
                s = filter(sub) 

                s_url = s[1].contents[1].get("href")
                if s_url.startswith(t_url):
                    sub_technique_url = urljoin(url, s_url)
                    sub_technique_name = s[2].contents[1].string.strip()
                    sub_technique_desc = s[3].get_text().strip()

                    sub_techniques.append({
                        "sub-technique": sub_technique_name,
                        "id": urlparse(technique_url).path.rstrip("/").split("/")[-1] + s[1].contents[1].string.strip() ,
                        "link": sub_technique_url,
                        "description": sub_technique_desc,
                    })

                    subtechniques.remove(sub)
           
            # Mitigations 
            mitigations = []
            r = requests.get(technique_url, verify=False)
            soup = BeautifulSoup(r.text, "html.parser")

            for m in soup.find_all(href=re.compile("/mitigations/M.+"))[1::2]: 
                mitigation_url = urljoin(url, m.get("href"))
                mitigation_name = m.string.strip()
                
                r = requests.get(mitigation_url, verify=False)
                soup = BeautifulSoup(r.text, "html.parser")
                mitigation_desc = soup.select("div.description-body")[0].contents[1].get_text().strip()

                mitigations.append({
                    "mitigation": mitigation_name,
                    "id": urlparse(mitigation_url).path.rstrip("/").split("/")[-1],
                    "link": mitigation_url,
                    "description": mitigation_desc,
                })

            # Create and append technique object
            technique_object = {
                "technique": technique_name,
                "id": urlparse(technique_url).path.rstrip("/").split("/")[-1],
                "link": technique_url,
                "description": technique_desc,
                "sub-techniques": sub_techniques,
                "mitigations": mitigations,
            }

            tactic_object["techniques"].append(technique_object)

        # Append tactic object
        mitre.append(tactic_object)

    with open(outfile, "w") as f:
        json.dump(mitre, f, ensure_ascii=False, indent=4)
    print("[+] MITRE ATT&CK data successfully written to file", outfile)

    # Create python files for Havoc plugin
    print("[*] Creating python file for each tactic...")
    for t in mitre:
        tactic = t["tactic"].lower().replace(" ", "_")
        with open(tactic + ".py", "w") as f:
            f.write(tactic + " = ")
            json.dump(t["techniques"], f, ensure_ascii=False, indent=4)
        print("[+] Created", tactic + ".py")

def main():
    fetch_mitre()

if __name__ == "__main__":
    main()
