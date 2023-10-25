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

from html_source.mitre import html_panel_mitre
from html_source.vulnerabilities import html_panel_vulns
from mitre.reconnaissance import reconnaissance_mitre

from vulns.network_vulnerabilities import network_vulns
from vulns.active_directory import active_directory_vulns 
from vulns.windows_privesc import windows_privesc_vulns 

tree_display_vulns = None
tree_display_mitre = None

net_titles = [item["title"] for item in network_vulns]
ad_titles = [item["title"] for item in active_directory_vulns]
winpriv_titles = [item["title"] for item in windows_privesc_vulns]

recon_mitre_titles = [item["title"] for item in reconnaissance_mitre]

# Function to set the HTML of the page
def select_tree_vulns(data):
    global tree_display_vulns
    title = ""
    desc = ""
    image = ""
    mitre = ""
    external = []
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

def select_tree_mitre(data):
    global tree_display_mitre
    title = ""
    mitreid = ""
    desc = ""
    image = ""
    sub_tech = []
    mitigations = []
    if data in recon_mitre_titles:
        title = reconnaissance_mitre[recon_mitre_titles.index(data)]["title"]
        mitreid= reconnaissance_mitre[recon_mitre_titles.index(data)]["mitreid"]
        desc = reconnaissance_mitre[recon_mitre_titles.index(data)]["description"]
        sub_tech = reconnaissance_mitre[recon_mitre_titles.index(data)]["sub-technique"]
        mitigations = reconnaissance_mitre[recon_mitre_titles.index(data)]["Mitigations"]
    subtech_data = ""
    mitigation_data = ""
    if title != "":
        if len(sub_tech) > 0:
            subtech_data = "<h3 style=\"color:#71e0cb\">Sub-techniques:</h3><ul>"
            for obj in sub_tech:
                subtech_data = subtech_data + "<li><a style=\"color:#e100ff\" href=\"%s\">%s</a></li>" % (obj["link"], obj["title"])
            subtech_data = subtech_data + "</ul>"
        if len(mitigations) > 0:
            mitigation_data = "<h3 style=\"color:#71e0cb\">Mitigations:</h3><table>"
            for obj in mitigations:
                mitigation_data = mitigation_data + "<tr><th><a style=\"color:#e100ff\" href=\"%s\">%s</a></th><th>%s</th></tr>" % (obj["link"], obj["title"], obj["description"])
        tree_display_mitre.setPanel(html_panel_mitre % (title, image, mitreid, desc, subtech_data, mitigation_data))

tree_display_mitre = havocui.Tree("MITRE ATTACK", select_tree_mitre, True)
tree_display_mitre.addRow("Reconnaissance", *recon_mitre_titles)

def open_vulns():
    tree_display_vulns.setBottomTab()
def open_mitre():
    tree_display_mitre.setBottomTab()
def color_pick():
    print(havocui.colordialog())

havocui.createtab("Reporter", "Vulnerabilities", open_vulns, "MITRE ATTACK", open_mitre, "color", color_pick)
