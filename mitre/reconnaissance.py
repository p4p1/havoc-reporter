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
    }
]
