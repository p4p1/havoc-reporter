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
import webbrowser
import os, sys, html, json

config = {
    "install_path": ""
}

# if no config file found create one
if not os.path.exists(os.path.expanduser("~/") + ".config/havoc-reporter/config.json"):
    if not os.path.exists(os.path.expanduser("~/") + ".config/havoc-reporter/"):
        os.mkdir(os.path.expanduser("~/") + ".config/havoc-reporter")
    with open(os.path.expanduser("~/") + ".config/havoc-reporter/config.json", "w") as outfile:
        json.dump(config, outfile)
else:  # use config file
    with open(os.path.expanduser("~/") + ".config/havoc-reporter/config.json") as outfile:
        config = json.load(outfile)

# specify here the path of the install script...
while not os.path.exists(config["install_path"]):
    new_path = havocui.inputdialog("specify the path of the install", "The path of where this script is installed is wrong please provide with the correct path:")
    config["install_path"] = new_path.decode('utf-8')
    with open(os.path.expanduser("~/") + ".config/havoc-reporter/config.json", "w") as outfile:
        json.dump(config, outfile)

sys.path.append(config["install_path"])

from html_source.mitre import html_panel_mitre
from html_source.vulnerabilities import html_panel_vulns

from mitre.tactics import * 

from vulns.network_vulnerabilities import network_vulns
from vulns.active_directory import active_directory_vulns 
from vulns.windows_privesc import windows_privesc_vulns 

tree_display_vulns = None
tree_display_mitre = None
settings_widget = None

net_titles = [item["title"] for item in network_vulns]
ad_titles = [item["title"] for item in active_directory_vulns]
winpriv_titles = [item["title"] for item in windows_privesc_vulns]

# MITRE ATT&CK techniques
reconnaissance_titles = [item["technique"] for item in reconnaissance]
resource_development_titles = [item["technique"] for item in resource_development]
initial_access_titles = [item["technique"] for item in initial_access]
execution_titles = [item["technique"] for item in execution]
persistence_titles = [item["technique"] for item in persistence]
privilege_escalation_titles = [item["technique"] for item in privilege_escalation]
defense_evasion_titles = [item["technique"] for item in defense_evasion]
credential_access_titles = [item["technique"] for item in credential_access]
discovery_titles = [item["technique"] for item in discovery]
lateral_movement_titles = [item["technique"] for item in lateral_movement]
collection_titles = [item["technique"] for item in collection]
command_and_control_titles = [item["technique"] for item in command_and_control]
exfiltration_titles = [item["technique"] for item in exfiltration]
impact_titles = [item["technique"] for item in impact]

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
    if data in reconnaissance_titles:
        image = ""
        title = reconnaissance[reconnaissance_titles.index(data)]["technique"]
        mitreid= reconnaissance[reconnaissance_titles.index(data)]["id"]
        desc = reconnaissance[reconnaissance_titles.index(data)]["description"]
        sub_tech = reconnaissance[reconnaissance_titles.index(data)]["sub-techniques"]
        mitigations = reconnaissance[reconnaissance_titles.index(data)]["mitigations"]
    if data in resource_development_titles:
        image = ""
        title = resource_development[resource_development_titles.index(data)]["technique"]
        mitreid= resource_development[resource_development_titles.index(data)]["id"]
        desc = resource_development[resource_development_titles.index(data)]["description"]
        sub_tech = resource_development[resource_development_titles.index(data)]["sub-techniques"]
        mitigations = resource_development[resource_development_titles.index(data)]["mitigations"]
    if data in initial_access_titles:
        image = ""
        title = initial_access[initial_access_titles.index(data)]["technique"]
        mitreid= initial_access[initial_access_titles.index(data)]["id"]
        desc = initial_access[initial_access_titles.index(data)]["description"]
        sub_tech = initial_access[initial_access_titles.index(data)]["sub-techniques"]
        mitigations = initial_access[initial_access_titles.index(data)]["mitigations"]
    if data in execution_titles:
        image = ""
        title = execution[execution_titles.index(data)]["technique"]
        mitreid= execution[execution_titles.index(data)]["id"]
        desc = execution[execution_titles.index(data)]["description"]
        sub_tech = execution[execution_titles.index(data)]["sub-techniques"]
        mitigations = execution[execution_titles.index(data)]["mitigations"]
    if data in persistence_titles:
        image = ""
        title = persistence[persistence_titles.index(data)]["technique"]
        mitreid= persistence[persistence_titles.index(data)]["id"]
        desc = persistence[persistence_titles.index(data)]["description"]
        sub_tech = persistence[persistence_titles.index(data)]["sub-techniques"]
        mitigations = persistence[persistence_titles.index(data)]["mitigations"]
    if data in privilege_escalation_titles:
        image = ""
        title = privilege_escalation[privilege_escalation_titles.index(data)]["technique"]
        mitreid= privilege_escalation[privilege_escalation_titles.index(data)]["id"]
        desc = privilege_escalation[privilege_escalation_titles.index(data)]["description"]
        sub_tech = privilege_escalation[privilege_escalation_titles.index(data)]["sub-techniques"]
        mitigations = privilege_escalation[privilege_escalation_titles.index(data)]["mitigations"]
    if data in defense_evasion_titles:
        image = ""
        title = defense_evasion[defense_evasion_titles.index(data)]["technique"]
        mitreid= defense_evasion[defense_evasion_titles.index(data)]["id"]
        desc = defense_evasion[defense_evasion_titles.index(data)]["description"]
        sub_tech = defense_evasion[defense_evasion_titles.index(data)]["sub-techniques"]
        mitigations = defense_evasion[defense_evasion_titles.index(data)]["mitigations"]
    if data in credential_access_titles:
        image = ""
        title = credential_access[credential_access_titles.index(data)]["technique"]
        mitreid= credential_access[credential_access_titles.index(data)]["id"]
        desc = credential_access[credential_access_titles.index(data)]["description"]
        sub_tech = credential_access[credential_access_titles.index(data)]["sub-techniques"]
        mitigations = credential_access[credential_access_titles.index(data)]["mitigations"]
    if data in discovery_titles:
        image = ""
        title = discovery[discovery_titles.index(data)]["technique"]
        mitreid= discovery[discovery_titles.index(data)]["id"]
        desc = discovery[discovery_titles.index(data)]["description"]
        sub_tech = discovery[discovery_titles.index(data)]["sub-techniques"]
        mitigations = discovery[discovery_titles.index(data)]["mitigations"]
    if data in lateral_movement_titles:
        image = ""
        title = lateral_movement[lateral_movement_titles.index(data)]["technique"]
        mitreid= lateral_movement[lateral_movement_titles.index(data)]["id"]
        desc = lateral_movement[lateral_movement_titles.index(data)]["description"]
        sub_tech = lateral_movement[lateral_movement_titles.index(data)]["sub-techniques"]
        mitigations = lateral_movement[lateral_movement_titles.index(data)]["mitigations"]
    if data in collection_titles:
        image = ""
        title = collection[collection_titles.index(data)]["technique"]
        mitreid= collection[collection_titles.index(data)]["id"]
        desc = collection[collection_titles.index(data)]["description"]
        sub_tech = collection[collection_titles.index(data)]["sub-techniques"]
        mitigations = collection[collection_titles.index(data)]["mitigations"]
    if data in command_and_control_titles:
        image = ""
        title = command_and_control[command_and_control_titles.index(data)]["technique"]
        mitreid= command_and_control[command_and_control_titles.index(data)]["id"]
        desc = command_and_control[command_and_control_titles.index(data)]["description"]
        sub_tech = command_and_control[command_and_control_titles.index(data)]["sub-techniques"]
        mitigations = command_and_control[command_and_control_titles.index(data)]["mitigations"]
    if data in exfiltration_titles:
        image = ""
        title = exfiltration[exfiltration_titles.index(data)]["technique"]
        mitreid= exfiltration[exfiltration_titles.index(data)]["id"]
        desc = exfiltration[exfiltration_titles.index(data)]["description"]
        sub_tech = exfiltration[exfiltration_titles.index(data)]["sub-techniques"]
        mitigations = exfiltration[exfiltration_titles.index(data)]["mitigations"]
    if data in impact_titles:
        image = ""
        title = impact[impact_titles.index(data)]["technique"]
        mitreid= impact[impact_titles.index(data)]["id"]
        desc = impact[impact_titles.index(data)]["description"]
        sub_tech = impact[impact_titles.index(data)]["sub-techniques"]
        mitigations = impact[impact_titles.index(data)]["mitigations"]
    subtech_data = ""
    mitigation_data = ""
    if title != "":
        if len(sub_tech) > 0:
            subtech_data = "<h3 style=\"color:#71e0cb\">Sub-techniques:</h3><ul>"
            for obj in sub_tech:
                subtech_data = subtech_data + "<li><a style=\"color:#e100ff\" href=\"%s\">%s: %s</a></li>" % (obj["link"], obj["id"], obj["sub-technique"])
            subtech_data = subtech_data + "</ul>"
        if len(mitigations) > 0:
            mitigation_data = "<h3 style=\"color:#71e0cb\">Mitigations:</h3><table>"
            for obj in mitigations:
                mitigation_data = mitigation_data + "<tr><th><a style=\"color:#e100ff\" href=\"%s\">%s</a></th><th>%s</th></tr>" % (obj["link"], obj["mitigation"], obj["description"])
        tree_display_mitre.setPanel(html_panel_mitre % (title, image, mitreid, desc, subtech_data, mitigation_data))

tree_display_mitre = havocui.Tree("MITRE ATTACK", select_tree_mitre, True)
tree_display_mitre.addRow("Reconnaissance", *reconnaissance_titles)
tree_display_mitre.addRow("Resource Development", *resource_development_titles)
tree_display_mitre.addRow("Initial Access", *initial_access_titles)
tree_display_mitre.addRow("Execution", *execution_titles)
tree_display_mitre.addRow("Persistence", *persistence_titles)
tree_display_mitre.addRow("Privilege Escalation", *privilege_escalation_titles)
tree_display_mitre.addRow("Defense Evasion", *defense_evasion_titles)
tree_display_mitre.addRow("Credential Access", *credential_access_titles)
tree_display_mitre.addRow("Discovery", *discovery_titles)
tree_display_mitre.addRow("Lateral Movement", *lateral_movement_titles)
tree_display_mitre.addRow("Collection", *collection_titles)
tree_display_mitre.addRow("Command and Control", *command_and_control_titles)
tree_display_mitre.addRow("Exfiltration", *exfiltration_titles)
tree_display_mitre.addRow("Impact", *impact_titles)

def change_config_path():
    global config
    tmp = config["install_path"]
    config["install_path"] = ""
    while not os.path.exists(config["install_path"]):
        new_path = havocui.inputdialog("specify the path of the install", "The path of where this script is installed is wrong please provide with the correct path:")
        config["install_path"] = new_path.decode('utf-8')
        with open(os.path.expanduser("~/") + ".config/havoc-reporter/config.json", "w") as outfile:
            json.dump(config, outfile)
    settings_widget.replaceLabel(tmp, config["install_path"])
def open_config_html_vuln():
    webbrowser.open(config["install_path"] + "/html_source/vulnerabilities.py")
def open_config_html_mitre():
    webbrowser.open(config["install_path"] + "/html_source/mitre.py")
# define settings widget
settings_widget = havocui.Widget("Reporter Settings", True)
settings_widget.addLabel("<h1 style='color:#bd93f9'>Reporter Settings</h1>")
settings_widget.addLabel("<h2 style='color:#71e0cb'>Install path:</h2>")
settings_widget.addLabel(config["install_path"])
settings_widget.addButton("Change path", change_config_path)
settings_widget.addLabel("<h2 style='color:#71e0cb'>Open HTML template:</h2>")
settings_widget.addButton("Open Vulnerabilities", open_config_html_vuln)
settings_widget.addButton("Open MITRE", open_config_html_mitre)

def open_vulns():
    tree_display_vulns.setBottomTab()
def open_mitre():
    tree_display_mitre.setBottomTab()
def open_settings():
    settings_widget.setSmallTab()
def color_pick():
    print(havocui.colordialog())

havocui.createtab("Reporter", "Vulnerabilities", open_vulns, "MITRE ATTACK", open_mitre, "Settings", open_settings,"Color", color_pick)
