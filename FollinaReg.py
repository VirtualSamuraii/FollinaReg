#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Author: VirtualSamurai
# Description: FollinaReg is a python script that automates the Follina (CVE-2022-30190) investigation process on multiple Windows workstations

import os
import time
from datetime import datetime
import requests
import json
import base64
from configparser import ConfigParser
import argparse
import winreg
from colorama import init, Fore
init(autoreset=True)


#  Initial Banner
def initBanner():
    print(Fore.RED + '''

    ███████╗ ██████╗ ██╗     ██╗     ██╗███╗   ██╗ █████╗ ██████╗ ███████╗ ██████╗
    ██╔════╝██╔═══██╗██║     ██║     ██║████╗  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝
    █████╗  ██║   ██║██║     ██║     ██║██╔██╗ ██║███████║██████╔╝█████╗  ██║  ███╗
    ██╔══╝  ██║   ██║██║     ██║     ██║██║╚██╗██║██╔══██║██╔══██╗██╔══╝  ██║   ██║
    ██║     ╚██████╔╝███████╗███████╗██║██║ ╚████║██║  ██║██║  ██║███████╗╚██████╔╝
    ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝

    Check the registry for Follina (CVE-2022-30190) artifacts on Windows workstations

    ''')


# Parsing script arguments
def parseArguments():
    parser = argparse.ArgumentParser(description="FollinaReg Help")
    parser.add_argument("-l", "--hosts-list", dest="hosts_list", action="store", type=str, required=True, help='List of workstations to check')
    return parser.parse_args()


# Enumerating users SIDs on the host
def enumerateSIDs(computer):
    sids = []
    access_registry = winreg.ConnectRegistry(computer,winreg.HKEY_USERS)
    access_key = winreg.OpenKey(access_registry,r"")
    for n in range(20):
       try:
          x = winreg.EnumKey(access_key,n)
          if "S-1-5-21" in x and not "_Classes" in x:
              sids.append(x)
       except:
          break
    return sids

# Check registry key for each user on each computer on the list
def investigateRegistry(computer):
    results_file = open(r"results.txt", "w+")
    results_file.write("===========================\n")
    results_file.write("Date: " + str(datetime.now()) + "\n")
    results_file.write("\n")
    urls = []
    sids = enumerateSIDs(computer)
    print("==============================================================")
    print("  Enumerating IPs and domains for computer: " + computer)
    print("==============================================================")
    results_file.write("\n")
    results_file.write("===========================\n")
    results_file.write("Computer: " + computer + "\n")
    results_file.write("===========================\n")
    for sid in sids:
        print("=====================================================")
        print("  SID: " + sid)
        print("=====================================================")
        results_file.write("SID: " + sid + "\n")
        path = sid + r"\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache"
        access_registry = winreg.ConnectRegistry(computer,winreg.HKEY_USERS)
        try:
            access_key = winreg.OpenKey(access_registry, path)
        except Exception as e:
            if e.errno == 2:
                print("There's no registry key on this computer !\n")
            elif e.errno == 53:
                print("Unknown computer !\n")
            else:
                print(e)
            break
        #accessing the key to open the registry directories under
        try:
            i = 0
            while True:
                item = winreg.EnumKey(access_key,i)
                urls.append(item)
                print(item)
                i += 1
        except:
            break


    for url in urls:
        analysis = scanVT(url)
        results_file.write("===========================================================\n")
        results_file.write("VirusTotal URL Scan Results for : " + str(url) + "\n")
        results_file.write("===========================================================\n")
        results_file.write(str(analysis) + "\n")
    results_file.close()


# Scan url using VirusTotal
def scanVT(url):
    config = ConfigParser()
    config.read('conf.cfg')
    VT_API_KEY = config.get('virustotal', 'api_key')
    vt_api_url = 'https://www.virustotal.com/api/v3/urls'
    headers = { "x-apikey" : VT_API_KEY }
    params = dict(url=url)
    response = requests.post(vt_api_url, data=params, headers=headers)
    if response.status_code == 200:
        result=response.json()
        url_id = base64.urlsafe_b64encode(params["url"].encode()).decode().strip("=")
        api_analysis_url = vt_api_url + "/" + url_id
        time.sleep(3)
        new_reponse = requests.get(api_analysis_url, headers=headers)
        analysis_result = new_reponse.json()
        print("===========================================================")
        print("VirusTotal URL Scan Results for : " + url)
        print("===========================================================")
        print(json.dumps(analysis_result["data"]["attributes"]["last_analysis_stats"], sort_keys=False, indent=4))
        return analysis_result["data"]["attributes"]["last_analysis_stats"]
    else:
        print("Please check your API Key and rate limit")


# Init Main
if __name__ == '__main__':

    # Initializing banner
    initBanner()

    # Parsing user arguments
    options = parseArguments()
    hosts_file = options.hosts_list
    computers = []
    with open(hosts_file) as f:
        lines = f.readlines()
    for line in lines:
        computers.append(r'{0}'.format(line.strip()))
    f.close()
    for computer in computers:
        investigateRegistry(computer)
