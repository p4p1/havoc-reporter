#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Made by papi
# Created on: Di 10 Okt 2023 01:54:42  CEST
# windows_privesc.py
# Description:
#  definition of the general windows privilege escalation vulnerabiltites.

windows_privesc_vulns = [
    {
        "title": "Unquoted Service Paths",
        "desc": "Exploiting services with unquoted service paths to execute malicious code as SYSTEM.",
        "image": "https://example.com/escalation-image.png",
        "mitre": "T1038",
        "external": [
            {
                "title": "Unquoted Service Paths - harmj0y",
                "link": "https://github.com/HarmJ0y/PowerUp"
            }
        ],
        "command": "N/A"
    },
    {
        "title": "DLL Hijacking",
        "desc": "Loading a malicious DLL in place of a legitimate DLL to execute arbitrary code.",
        "image": "https://example.com/escalation-image.png",
        "mitre": "T1574",
        "external": [
            {
                "title": "DLL Hijacking - harmj0y",
                "link": "https://github.com/HarmJ0y/PowerUp"
            }
        ],
        "command": "N/A"
    },
    {
        "title": "AlwaysInstallElevated",
        "desc": "Exploiting the AlwaysInstallElevated registry key to install MSI files with elevated privileges.",
        "image": "https://example.com/escalation-image.png",
        "mitre": "T1546.011",
        "external": [
            {
                "title": "AlwaysInstallElevated - LOLBAS",
                "link": "https://lolbas-project.github.io/lolbas/Binaries/AlwaysInstallElevated/"
            }
        ],
        "command": "msiexec /quiet /qn /i <malicious.msi>"
    },
    {
        "title": "Registry Run Keys/Startup Folders",
        "desc": "Adding malicious entries to registry run keys or startup folders for persistent execution.",
        "image": "https://example.com/escalation-image.png",
        "mitre": "T1547.001",
        "external": [
            {
                "title": "Adding a Run Key - LOLBAS",
                "link": "https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/"
            }
        ],
        "command": "N/A"
    },
    {
        "title": "Named Pipes",
        "desc": "Exploiting named pipes for privilege escalation.",
        "image": "https://example.com/escalation-image.png",
        "mitre": "T1034",
        "external": [
            {
                "title": "Windows Named Pipe Penetration - SANS",
                "link": "https://www.sans.org/blog/windows-named-pipe-penetration-part-1-exploiting-named-pipes-smb-named-pipes/"
            }
        ],
        "command": "N/A"
    },
    {
        "title": "Task Scheduler",
        "desc": "Abusing the Task Scheduler service to execute arbitrary code with SYSTEM privileges.",
        "image": "https://example.com/escalation-image.png",
        "mitre": "T1053",
        "external": [
            {
                "title": "Abusing Windows Task Scheduler",
                "link": "https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#tasksch"
            }
        ],
        "command": "N/A"
    },
    {
        "title": "Service Control Manager",
        "desc": "Modifying service configurations or replacing services to achieve privilege escalation.",
        "image": "https://example.com/escalation-image.png",
        "mitre": "T1543.003",
        "external": [
            {
                "title": "Modifying Services - LOLBAS",
                "link": "https://lolbas-project.github.io/lolbas/Binaries/Sc.exe/"
            }
        ],
        "command": "N/A"
    }
]
