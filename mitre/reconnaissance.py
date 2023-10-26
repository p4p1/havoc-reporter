reconnaissance_mitre = [
    {
        "title": "Active Scanning",
        "mitreid": "T1595",
        "description": "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting. Active scans are those where the adversary probes victim infrastructure via network traffic, as opposed to other forms of reconnaissance that do not involve direct interaction.",
        "sub-technique": [
            {
                "title": "Scanning IP Blocks",
                "link": "https://attack.mitre.org/techniques/T1595/001/"
            },
            {
                "title": "Vulnerability Scanning",
                "link": "https://attack.mitre.org/techniques/T1595/002/"
            },
            {
                "title": "Wordlist Scanning",
                "link": "https://attack.mitre.org/techniques/T1595/003/"
            }
        ],
        "Mitigations": [
            {
                "title": "Pre-compromise",
                "description": "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on minimizing the amount and sensitivity of data available to external parties.",
                "link": "https://attack.mitre.org/mitigations/M1056"
            }
        ]
    },
    {
        "title": "Gather Victim Host Information",
        "mitreid": "T1592",
        "description": "Adversaries may gather information about the victim's hosts that can be used during targeting. Information about hosts may include a variety of details, including administrative data (ex: name, assigned IP, functionality, etc.) as well as specifics regarding its configuration (ex: operating system, language, etc.).",
        "sub-technique": [
            {
                "title": "Hardware",
                "link": "https://attack.mitre.org/techniques/T1592/001/"
            },
            {
                "title": "Software",
                "link": "https://attack.mitre.org/techniques/T1592/002/"
            },
            {
                "title": "Firmware",
                "link": "https://attack.mitre.org/techniques/T1592/003/"
            },
            {
                "title": "Client Configuration",
                "link": "https://attack.mitre.org/techniques/T1592/004/"
            }
        ],
        "Mitigations": [
            {
                "title": "Pre-compromise",
                "description": "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on minimizing the amount and sensitivity of data available to external parties.",
                "link": "https://attack.mitre.org/mitigations/M1056"
            }
        ]
    },
    {
        "title": "Gather Victim Identity Information",
        "mitreid": "T1589",
        "description": "Adversaries may gather information about the victim's identity that can be used during targeting. Information about identities may include a variety of details, including personal data (ex: employee names, email addresses, etc.) as well as sensitive details such as credentials.",
        "sub-technique": [
            {
                "title": "Credentials",
                "link": "https://attack.mitre.org/techniques/T1589/001/"
            },
            {
                "title": "Email Addresses",
                "link": "https://attack.mitre.org/techniques/T1589/002/"
            },
            {
                "title": "Employee Names",
                "link": "https://attack.mitre.org/techniques/T1589/003/"
            }
        ],
        "Mitigations": [
            {
                "title": "Pre-compromise",
                "description": "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on minimizing the amount and sensitivity of data available to external parties.",
                "link": "https://attack.mitre.org/mitigations/M1056"
            }
        ]
    },
    {
        "title": "Gather Victim Network Information",
        "mitreid": "T1590",
        "description": "Adversaries may gather information about the victim's networks that can be used during targeting. Information about networks may include a variety of details, including administrative data (ex: IP ranges, domain names, etc.) as well as specifics regarding its topology and operations.",
        "sub-technique": [
            {
                "title": "Domain Properties",
                "link": "https://attack.mitre.org/techniques/T1590/001/"
            },
            {
                "title": "DNS",
                "link": "https://attack.mitre.org/techniques/T1590/002/"
            },
            {
                "title": "Network Trust Dependencies",
                "link": "https://attack.mitre.org/techniques/T1590/003/"
            },
            {
                "title": "Network Topology",
                "link": "https://attack.mitre.org/techniques/T1590/004/"
            },
            {
                "title": "IP Addresses",
                "link": "https://attack.mitre.org/techniques/T1590/005/"
            },
            {
                "title": "Network Security Appliance",
                "link": "https://attack.mitre.org/techniques/T1590/006/"
            }
        ],
        "Mitigations": [
            {
                "title": "Pre-compromise",
                "description": "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on minimizing the amount and sensitivity of data available to external parties.",
                "link": "https://attack.mitre.org/mitigations/M1056"
            }
        ]
    },
    {
        "title": "Gather Victim Org Information",
        "mitreid": "T1591",
        "description": "Adversaries may gather information about the victim's organization that can be used during targeting. Information about an organization may include a variety of details, including the names of divisions/departments, specifics of business operations, as well as the roles and responsibilities of key employees.",
        "sub-technique": [
            {
                "title": "Physical Location",
                "link": "https://attack.mitre.org/techniques/T1591/001/"
            },
            {
                "title": "Business Relationships",
                "link": "https://attack.mitre.org/techniques/T1591/002/"
            },
            {
                "title": "Identify Business Tempo",
                "link": "https://attack.mitre.org/techniques/T1591/003/"
            },
            {
                "title": "Identify Roles",
                "link": "https://attack.mitre.org/techniques/T1591/004/"
            }
        ],
        "Mitigations": [
            {
                "title": "Pre-compromise",
                "description": "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on minimizing the amount and sensitivity of data available to external parties.",
                "link": "https://attack.mitre.org/mitigations/M1056"
            }
        ]
    },
    {
        "title": "Phishing for Information",
        "mitreid": "T1598",
        "description": "Adversaries may send phishing messages to elicit sensitive information that can be used during targeting. Phishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Phishing for information is different from Phishing in that the objective is gathering data from the victim rather than executing malicious code.",
        "sub-technique": [
            {
                "title": "Spearphishing service",
                "link": "https://attack.mitre.org/techniques/T1598/001/"
            },
            {
                "title": "Spearphishing Attachment",
                "link": "https://attack.mitre.org/techniques/T1598/002/"
            },
            {
                "title": "Spearphishing Link",
                "link": "https://attack.mitre.org/techniques/T1598/003/"
            }
        ],
        "Mitigations": [
            {
                "title": "Software Configuration",
                "description": "Use anti-spoofing and email authentication mechanisms to filter messages based on validity checks of the sender domain (using SPF) and integrity of messages (using DKIM). Enabling these mechanisms within an organization (through policies such as DMARC) may enable recipients (intra-org and cross domain) to perform similar message filtering and validation.",
                "link": "https://attack.mitre.org/mitigations/M1054"
            },
            {
                "title": "User Training",
                "description": "Users can be trained to identify social engineering techniques and spearphishing attempts.",
                "link": "https://attack.mitre.org/mitigations/M1017"
            }
        ]
    }
]
