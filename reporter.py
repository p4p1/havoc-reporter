#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Made by papi
# Created on: Wen 25 Oct 2023
# reporter.py
# Description:
#  A havoc extention to provide examples for different vulnerabilities that can
#  be tested on the infected networks and on the infected machines.
# Usage:
#  To use this script save it on your machine and add it to the script manager of Havoc
#  inside of: Scripts > Scripts Manager > Load Script

import havocui
import os, sys, html

# specify here the path of the install script...
sys.path.append("/home/p4p1/Documents/lnd/havoc-reporter/")

from network_vulnerabilities import network_vulns
from active_directory import active_directory_vulns 
from windows_privesc import windows_privesc_vulns 

tree_display_vulns = None
html_panel_vulns = """
<div>
    <h1 style="color:#bd93f9">%s</h1><br />
    <img src="%s" width="100" />
    <table>
        <tr>
            <th>MITRE ATT&CK ID: </th>
            <th style="color: #f96769">%s</th>
        </tr>
    </table>
    <h3 style="color:#71e0cb">Description:</h3>
    <p>%s</p>
    <h3 style="color:#71e0cb">Sample command:</h3>
    <div style="background-color:#3b3e50; padding: 5px 5px 5px 5px;">
        <p>%s</p>
    </div>
    <h3 style="color:#71e0cb">Resources:</h3>
    <ul>
        %s
    </ul>
</div>
"""

net_titles = [item["title"] for item in network_vulns]
ad_titles = [item["title"] for item in active_directory_vulns]
winpriv_titles = [item["title"] for item in windows_privesc_vulns]

# Function to set the HTML of the page
def select_tree_vulns(data):
    global tree_display_vulns
    title = ""
    desc = ""
    image = ""
    mitre = ""
    external = ""
    command = ""
    if data in net_titles:
        title = network_vulns[net_titles.index(data)]["title"]
        desc = network_vulns[net_titles.index(data)]["desc"]
        image = network_vulns[net_titles.index(data)]["image"]
        mitre = network_vulns[net_titles.index(data)]["mitre"]
        external = network_vulns[net_titles.index(data)]["external"]
        command = network_vulns[net_titles.index(data)]["command"]
    elif data in ad_titles:
        title = active_directory_vulns[ad_titles.index(data)]["title"]
        desc = active_directory_vulns[ad_titles.index(data)]["desc"]
        image = active_directory_vulns[ad_titles.index(data)]["image"]
        mitre = active_directory_vulns[ad_titles.index(data)]["mitre"]
        external = active_directory_vulns[ad_titles.index(data)]["external"]
        command = active_directory_vulns[ad_titles.index(data)]["command"]
    elif data in winpriv_titles:
        title = windows_privesc_vulns[winpriv_titles.index(data)]["title"]
        desc = windows_privesc_vulns[winpriv_titles.index(data)]["desc"]
        image = windows_privesc_vulns[winpriv_titles.index(data)]["image"]
        mitre = windows_privesc_vulns[winpriv_titles.index(data)]["mitre"]
        external = windows_privesc_vulns[winpriv_titles.index(data)]["external"]
        command = windows_privesc_vulns[winpriv_titles.index(data)]["command"]

    if title != "":
        external_data = ""
        for obj in external:
            external_data = external_data + "<li><a style=\"color:#e100ff\" href=\"%s\">%s</a></li>" % (obj["link"], obj["title"])
        tree_display_vulns.setPanel(html_panel_vulns % (title, image, mitre, desc, html.escape(command), external_data))

tree_display_vulns = havocui.Tree("Vulnerabilities", select_tree_vulns, True)
tree_display_vulns.addRow("General Network", *net_titles)
tree_display_vulns.addRow("Active Directory", *ad_titles)
tree_display_vulns.addRow("Windows Privilege Escalation", *winpriv_titles)

def open_vulns():
    tree_display_vulns.setBottomTab()
def color_pick():
    print(havocui.colordialog())

havocui.createtab("Reporter", "Vulnerabilities", open_vulns, "color", color_pick)
