reconnaissance = [
    {
        "technique": "Active Scanning",
        "id": "T1595",
        "link": "https://attack.mitre.org/techniques/T1595",
        "description": "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting. Active scans are those where the adversary probes victim infrastructure via network traffic, as opposed to other forms of reconnaissance that do not involve direct interaction.",
        "sub-techniques": [
            {
                "sub-technique": "Scanning IP Blocks",
                "id": "T1595.001",
                "link": "https://attack.mitre.org/techniques/T1595/001",
                "description": "Adversaries may scan victim IP blocks to gather information that can be used during targeting. Public IP addresses may be allocated to organizations by block, or a range of sequential addresses."
            },
            {
                "sub-technique": "Wordlist Scanning",
                "id": "T1595.003",
                "link": "https://attack.mitre.org/techniques/T1595/003",
                "description": "Adversaries may iteratively probe infrastructure using brute-forcing and crawling techniques. While this technique employs similar methods to Brute Force, its goal is the identification of content and infrastructure rather than the discovery of valid credentials. Wordlists used in these scans may contain generic, commonly used names and file extensions or terms specific to a particular software. Adversaries may also create custom, target-specific wordlists using data gathered from other Reconnaissance techniques (ex: Gather Victim Org Information, or Search Victim-Owned Websites)."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Pre-compromise",
                "id": "M1056",
                "link": "https://attack.mitre.org/mitigations/M1056",
                "description": "This category is used for any applicable mitigation activities that apply to techniques occurring before an adversary gains Initial Access, such as Reconnaissance and Resource Development techniques."
            }
        ]
    },
    {
        "technique": "Gather Victim Host Information",
        "id": "T1592",
        "link": "https://attack.mitre.org/techniques/T1592",
        "description": "Adversaries may gather information about the victim's hosts that can be used during targeting. Information about hosts may include a variety of details, including administrative data (ex: name, assigned IP, functionality, etc.) as well as specifics regarding its configuration (ex: operating system, language, etc.).",
        "sub-techniques": [
            {
                "sub-technique": "Hardware",
                "id": "T1592.001",
                "link": "https://attack.mitre.org/techniques/T1592/001",
                "description": "Adversaries may gather information about the victim's host hardware that can be used during targeting. Information about hardware infrastructure may include a variety of details such as types and versions on specific hosts, as well as the presence of additional components that might be indicative of added defensive protections (ex: card/biometric readers, dedicated encryption hardware, etc.)."
            },
            {
                "sub-technique": "Firmware",
                "id": "T1592.003",
                "link": "https://attack.mitre.org/techniques/T1592/003",
                "description": "Adversaries may gather information about the victim's host firmware that can be used during targeting. Information about host firmware may include a variety of details such as type and versions on specific hosts, which may be used to infer more information about hosts in the environment (ex: configuration, purpose, age/patch level, etc.)."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Pre-compromise",
                "id": "M1056",
                "link": "https://attack.mitre.org/mitigations/M1056",
                "description": "This category is used for any applicable mitigation activities that apply to techniques occurring before an adversary gains Initial Access, such as Reconnaissance and Resource Development techniques."
            }
        ]
    },
    {
        "technique": "Gather Victim Identity Information",
        "id": "T1589",
        "link": "https://attack.mitre.org/techniques/T1589",
        "description": "Adversaries may gather information about the victim's identity that can be used during targeting. Information about identities may include a variety of details, including personal data (ex: employee names, email addresses, etc.) as well as sensitive details such as credentials.",
        "sub-techniques": [
            {
                "sub-technique": "Credentials",
                "id": "T1589.001",
                "link": "https://attack.mitre.org/techniques/T1589/001",
                "description": "Adversaries may gather credentials that can be used during targeting. Account credentials gathered by adversaries may be those directly associated with the target victim organization or attempt to take advantage of the tendency for users to use the same passwords across personal and business accounts."
            },
            {
                "sub-technique": "Employee Names",
                "id": "T1589.003",
                "link": "https://attack.mitre.org/techniques/T1589/003",
                "description": "Adversaries may gather employee names that can be used during targeting. Employee names be used to derive email addresses as well as to help guide other reconnaissance efforts and/or craft more-believable lures."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Pre-compromise",
                "id": "M1056",
                "link": "https://attack.mitre.org/mitigations/M1056",
                "description": "This category is used for any applicable mitigation activities that apply to techniques occurring before an adversary gains Initial Access, such as Reconnaissance and Resource Development techniques."
            }
        ]
    },
    {
        "technique": "Gather Victim Network Information",
        "id": "T1590",
        "link": "https://attack.mitre.org/techniques/T1590",
        "description": "Adversaries may gather information about the victim's networks that can be used during targeting. Information about networks may include a variety of details, including administrative data (ex: IP ranges, domain names, etc.) as well as specifics regarding its topology and operations.",
        "sub-techniques": [
            {
                "sub-technique": "Domain Properties",
                "id": "T1590.001",
                "link": "https://attack.mitre.org/techniques/T1590/001",
                "description": "Adversaries may gather information about the victim's network domain(s) that can be used during targeting. Information about domains and their properties may include a variety of details, including what domain(s) the victim owns as well as administrative data (ex: name, registrar, etc.) and more directly actionable information such as contacts (email addresses and phone numbers), business addresses, and name servers."
            },
            {
                "sub-technique": "Network Trust Dependencies",
                "id": "T1590.003",
                "link": "https://attack.mitre.org/techniques/T1590/003",
                "description": "Adversaries may gather information about the victim's network trust dependencies that can be used during targeting. Information about network trusts may include a variety of details, including second or third-party organizations/domains (ex: managed service providers, contractors, etc.) that have connected (and potentially elevated) network access."
            },
            {
                "sub-technique": "IP Addresses",
                "id": "T1590.005",
                "link": "https://attack.mitre.org/techniques/T1590/005",
                "description": "Adversaries may gather the victim's IP addresses that can be used during targeting. Public IP addresses may be allocated to organizations by block, or a range of sequential addresses. Information about assigned IP addresses may include a variety of details, such as which IP addresses are in use. IP addresses may also enable an adversary to derive other details about a victim, such as organizational size, physical location(s), Internet service provider, and or where/how their publicly-facing infrastructure is hosted."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Pre-compromise",
                "id": "M1056",
                "link": "https://attack.mitre.org/mitigations/M1056",
                "description": "This category is used for any applicable mitigation activities that apply to techniques occurring before an adversary gains Initial Access, such as Reconnaissance and Resource Development techniques."
            }
        ]
    },
    {
        "technique": "Gather Victim Org Information",
        "id": "T1591",
        "link": "https://attack.mitre.org/techniques/T1591",
        "description": "Adversaries may gather information about the victim's organization that can be used during targeting. Information about an organization may include a variety of details, including the names of divisions/departments, specifics of business operations, as well as the roles and responsibilities of key employees.",
        "sub-techniques": [
            {
                "sub-technique": "Determine Physical Locations",
                "id": "T1591.001",
                "link": "https://attack.mitre.org/techniques/T1591/001",
                "description": "Adversaries may gather the victim's physical location(s) that can be used during targeting. Information about physical locations of a target organization may include a variety of details, including where key resources and infrastructure are housed. Physical locations may also indicate what legal jurisdiction and/or authorities the victim operates within."
            },
            {
                "sub-technique": "Identify Business Tempo",
                "id": "T1591.003",
                "link": "https://attack.mitre.org/techniques/T1591/003",
                "description": "Adversaries may gather information about the victim's business tempo that can be used during targeting. Information about an organization’s business tempo may include a variety of details, including operational hours/days of the week. This information may also reveal times/dates of purchases and shipments of the victim’s hardware and software resources."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Pre-compromise",
                "id": "M1056",
                "link": "https://attack.mitre.org/mitigations/M1056",
                "description": "This category is used for any applicable mitigation activities that apply to techniques occurring before an adversary gains Initial Access, such as Reconnaissance and Resource Development techniques."
            }
        ]
    },
    {
        "technique": "Phishing for Information",
        "id": "T1598",
        "link": "https://attack.mitre.org/techniques/T1598",
        "description": "Adversaries may send phishing messages to elicit sensitive information that can be used during targeting. Phishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Phishing for information is different from Phishing in that the objective is gathering data from the victim rather than executing malicious code.",
        "sub-techniques": [
            {
                "sub-technique": "Spearphishing Service",
                "id": "T1598.001",
                "link": "https://attack.mitre.org/techniques/T1598/001",
                "description": "Adversaries may send spearphishing messages via third-party services to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: Establish Accounts or Compromise Accounts) and/or sending multiple, seemingly urgent messages."
            },
            {
                "sub-technique": "Spearphishing Link",
                "id": "T1598.003",
                "link": "https://attack.mitre.org/techniques/T1598/003",
                "description": "Adversaries may send spearphishing messages with a malicious link to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: Establish Accounts or Compromise Accounts) and/or sending multiple, seemingly urgent messages."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Software Configuration",
                "id": "M1054",
                "link": "https://attack.mitre.org/mitigations/M1054",
                "description": "Implement configuration changes to software (other than the operating system) to mitigate security risks associated to how the software operates."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    },
    {
        "technique": "Search Closed Sources",
        "id": "T1597",
        "link": "https://attack.mitre.org/techniques/T1597",
        "description": "Adversaries may search and gather information about victims from closed sources that can be used during targeting. Information about victims may be available for purchase from reputable private sources and databases, such as paid subscriptions to feeds of technical/threat intelligence data. Adversaries may also purchase information from less-reputable sources such as dark web or cybercrime blackmarkets.",
        "sub-techniques": [
            {
                "sub-technique": "Threat Intel Vendors",
                "id": "T1597.001",
                "link": "https://attack.mitre.org/techniques/T1597/001",
                "description": "Adversaries may search private data from threat intelligence vendors for information that can be used during targeting. Threat intelligence vendors may offer paid feeds or portals that offer more data than what is publicly reported. Although sensitive details (such as customer names and other identifiers) may be redacted, this information may contain trends regarding breaches such as target industries, attribution claims, and successful TTPs/countermeasures."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Pre-compromise",
                "id": "M1056",
                "link": "https://attack.mitre.org/mitigations/M1056",
                "description": "This category is used for any applicable mitigation activities that apply to techniques occurring before an adversary gains Initial Access, such as Reconnaissance and Resource Development techniques."
            }
        ]
    },
    {
        "technique": "Search Open Technical Databases",
        "id": "T1596",
        "link": "https://attack.mitre.org/techniques/T1596",
        "description": "Adversaries may search freely available technical databases for information about victims that can be used during targeting. Information about victims may be available in online databases and repositories, such as registrations of domains/certificates as well as public collections of network data/artifacts gathered from traffic and/or scans.",
        "sub-techniques": [
            {
                "sub-technique": "DNS/Passive DNS",
                "id": "T1596.001",
                "link": "https://attack.mitre.org/techniques/T1596/001",
                "description": "Adversaries may search DNS data for information about victims that can be used during targeting. DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts."
            },
            {
                "sub-technique": "Digital Certificates",
                "id": "T1596.003",
                "link": "https://attack.mitre.org/techniques/T1596/003",
                "description": "Adversaries may search public digital certificate data for information about victims that can be used during targeting. Digital certificates are issued by a certificate authority (CA) in order to cryptographically verify the origin of signed content. These certificates, such as those used for encrypted web traffic (HTTPS SSL/TLS communications), contain information about the registered organization such as name and location."
            },
            {
                "sub-technique": "Scan Databases",
                "id": "T1596.005",
                "link": "https://attack.mitre.org/techniques/T1596/005",
                "description": "Adversaries may search within public scan databases for information about victims that can be used during targeting. Various online services continuously publish the results of Internet scans/surveys, often harvesting information such as active IP addresses, hostnames, open ports, certificates, and even server banners."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Pre-compromise",
                "id": "M1056",
                "link": "https://attack.mitre.org/mitigations/M1056",
                "description": "This category is used for any applicable mitigation activities that apply to techniques occurring before an adversary gains Initial Access, such as Reconnaissance and Resource Development techniques."
            }
        ]
    },
    {
        "technique": "Search Open Websites/Domains",
        "id": "T1593",
        "link": "https://attack.mitre.org/techniques/T1593",
        "description": "Adversaries may search freely available websites and/or domains for information about victims that can be used during targeting. Information about victims may be available in various online sites, such as social media, new sites, or those hosting information about business operations such as hiring or requested/rewarded contracts.",
        "sub-techniques": [
            {
                "sub-technique": "Social Media",
                "id": "T1593.001",
                "link": "https://attack.mitre.org/techniques/T1593/001",
                "description": "Adversaries may search social media for information about victims that can be used during targeting. Social media sites may contain various information about a victim organization, such as business announcements as well as information about the roles, locations, and interests of staff."
            },
            {
                "sub-technique": "Code Repositories",
                "id": "T1593.003",
                "link": "https://attack.mitre.org/techniques/T1593/003",
                "description": "Adversaries may search public code repositories for information about victims that can be used during targeting. Victims may store code in repositories on various third-party websites such as GitHub, GitLab, SourceForge, and BitBucket. Users typically interact with code repositories through a web application or command-line utilities such as git."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Application Developer Guidance",
                "id": "M1013",
                "link": "https://attack.mitre.org/mitigations/M1013",
                "description": "This mitigation describes any guidance or training given to developers of applications to avoid introducing security weaknesses that an adversary may be able to take advantage of."
            },
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            }
        ]
    },
    {
        "technique": "Search Victim-Owned Websites",
        "id": "T1594",
        "link": "https://attack.mitre.org/techniques/T1594",
        "description": "Adversaries may search websites owned by the victim for information that can be used during targeting. Victim-owned websites may contain a variety of details, including names of departments/divisions, physical locations, and data about key employees such as names, roles, and contact info (ex: Email Addresses). These sites may also have details highlighting business operations and relationships.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Pre-compromise",
                "id": "M1056",
                "link": "https://attack.mitre.org/mitigations/M1056",
                "description": "This category is used for any applicable mitigation activities that apply to techniques occurring before an adversary gains Initial Access, such as Reconnaissance and Resource Development techniques."
            }
        ]
    }
]

resource_development = [
    {
        "technique": "Acquire Access",
        "id": "T1650",
        "link": "https://attack.mitre.org/techniques/T1650",
        "description": "Adversaries may purchase or otherwise acquire an existing access to a target system or network. A variety of online services and initial access broker networks are available to sell access to previously compromised systems. In some cases, adversary groups may form partnerships to share compromised systems with each other.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Pre-compromise",
                "id": "M1056",
                "link": "https://attack.mitre.org/mitigations/M1056",
                "description": "This category is used for any applicable mitigation activities that apply to techniques occurring before an adversary gains Initial Access, such as Reconnaissance and Resource Development techniques."
            }
        ]
    },
    {
        "technique": "Acquire Infrastructure",
        "id": "T1583",
        "link": "https://attack.mitre.org/techniques/T1583",
        "description": "Adversaries may buy, lease, or rent infrastructure that can be used during targeting. A wide variety of infrastructure exists for hosting and orchestrating adversary operations. Infrastructure solutions include physical or cloud servers, domains, and third-party web services. Additionally, botnets are available for rent or purchase.",
        "sub-techniques": [
            {
                "sub-technique": "Domains",
                "id": "T1583.001",
                "link": "https://attack.mitre.org/techniques/T1583/001",
                "description": "Adversaries may acquire domains that can be used during targeting. Domain names are the human readable names used to represent one or more IP addresses. They can be purchased or, in some cases, acquired for free."
            },
            {
                "sub-technique": "Virtual Private Server",
                "id": "T1583.003",
                "link": "https://attack.mitre.org/techniques/T1583/003",
                "description": "Adversaries may rent Virtual Private Servers (VPSs) that can be used during targeting. There exist a variety of cloud service providers that will sell virtual machines/containers as a service. By utilizing a VPS, adversaries can make it difficult to physically tie back operations to them. The use of cloud infrastructure can also make it easier for adversaries to rapidly provision, modify, and shut down their infrastructure."
            },
            {
                "sub-technique": "Botnet",
                "id": "T1583.005",
                "link": "https://attack.mitre.org/techniques/T1583/005",
                "description": "Adversaries may buy, lease, or rent a network of compromised systems that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks. Adversaries may purchase a subscription to use an existing botnet from a booter/stresser service. With a botnet at their disposal, adversaries may perform follow-on activity such as large-scale Phishing or Distributed Denial of Service (DDoS)."
            },
            {
                "sub-technique": "Serverless",
                "id": "T1583.007",
                "link": "https://attack.mitre.org/techniques/T1583/007",
                "description": "Adversaries may purchase and configure serverless cloud infrastructure, such as Cloudflare Workers or AWS Lambda functions, that can be used during targeting. By utilizing serverless infrastructure, adversaries can make it more difficult to attribute infrastructure used during operations back to them."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Pre-compromise",
                "id": "M1056",
                "link": "https://attack.mitre.org/mitigations/M1056",
                "description": "This category is used for any applicable mitigation activities that apply to techniques occurring before an adversary gains Initial Access, such as Reconnaissance and Resource Development techniques."
            }
        ]
    },
    {
        "technique": "Compromise Accounts",
        "id": "T1586",
        "link": "https://attack.mitre.org/techniques/T1586",
        "description": "Adversaries may compromise accounts with services that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating accounts (i.e. Establish Accounts), adversaries may compromise existing accounts. Utilizing an existing persona may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona.",
        "sub-techniques": [
            {
                "sub-technique": "Social Media Accounts",
                "id": "T1586.001",
                "link": "https://attack.mitre.org/techniques/T1586/001",
                "description": "Adversaries may compromise social media accounts that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating social media profiles (i.e. Social Media Accounts), adversaries may compromise existing social media accounts. Utilizing an existing persona may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona."
            },
            {
                "sub-technique": "Cloud Accounts",
                "id": "T1586.003",
                "link": "https://attack.mitre.org/techniques/T1586/003",
                "description": "Adversaries may compromise cloud accounts that can be used during targeting. Adversaries can use compromised cloud accounts to further their operations, including leveraging cloud storage services such as Dropbox, Microsoft OneDrive, or AWS S3 buckets for Exfiltration to Cloud Storage or to Upload Tools. Cloud accounts can also be used in the acquisition of infrastructure, such as Virtual Private Servers or Serverless infrastructure. Compromising cloud accounts may allow adversaries to develop sophisticated capabilities without managing their own servers."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Pre-compromise",
                "id": "M1056",
                "link": "https://attack.mitre.org/mitigations/M1056",
                "description": "This category is used for any applicable mitigation activities that apply to techniques occurring before an adversary gains Initial Access, such as Reconnaissance and Resource Development techniques."
            }
        ]
    },
    {
        "technique": "Compromise Infrastructure",
        "id": "T1584",
        "link": "https://attack.mitre.org/techniques/T1584",
        "description": "Adversaries may compromise third-party infrastructure that can be used during targeting. Infrastructure solutions include physical or cloud servers, domains, and third-party web and DNS services. Instead of buying, leasing, or renting infrastructure an adversary may compromise infrastructure and use it during other phases of the adversary lifecycle. Additionally, adversaries may compromise numerous machines to form a botnet they can leverage.",
        "sub-techniques": [
            {
                "sub-technique": "Domains",
                "id": "T1584.001",
                "link": "https://attack.mitre.org/techniques/T1584/001",
                "description": "Adversaries may hijack domains and/or subdomains that can be used during targeting. Domain registration hijacking is the act of changing the registration of a domain name without the permission of the original registrant. Adversaries may gain access to an email account for the person listed as the owner of the domain. The adversary can then claim that they forgot their password in order to make changes to the domain registration. Other possibilities include social engineering a domain registration help desk to gain access to an account or taking advantage of renewal process gaps."
            },
            {
                "sub-technique": "Virtual Private Server",
                "id": "T1584.003",
                "link": "https://attack.mitre.org/techniques/T1584/003",
                "description": "Adversaries may compromise third-party Virtual Private Servers (VPSs) that can be used during targeting. There exist a variety of cloud service providers that will sell virtual machines/containers as a service. Adversaries may compromise VPSs purchased by third-party entities. By compromising a VPS to use as infrastructure, adversaries can make it difficult to physically tie back operations to themselves."
            },
            {
                "sub-technique": "Botnet",
                "id": "T1584.005",
                "link": "https://attack.mitre.org/techniques/T1584/005",
                "description": "Adversaries may compromise numerous third-party systems to form a botnet that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks. Instead of purchasing/renting a botnet from a booter/stresser service, adversaries may build their own botnet by compromising numerous third-party systems. Adversaries may also conduct a takeover of an existing botnet, such as redirecting bots to adversary-controlled C2 servers. With a botnet at their disposal, adversaries may perform follow-on activity such as large-scale Phishing or Distributed Denial of Service (DDoS)."
            },
            {
                "sub-technique": "Serverless",
                "id": "T1584.007",
                "link": "https://attack.mitre.org/techniques/T1584/007",
                "description": "Adversaries may compromise serverless cloud infrastructure, such as Cloudflare Workers or AWS Lambda functions, that can be used during targeting. By utilizing serverless infrastructure, adversaries can make it more difficult to attribute infrastructure used during operations back to them."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Pre-compromise",
                "id": "M1056",
                "link": "https://attack.mitre.org/mitigations/M1056",
                "description": "This category is used for any applicable mitigation activities that apply to techniques occurring before an adversary gains Initial Access, such as Reconnaissance and Resource Development techniques."
            }
        ]
    },
    {
        "technique": "Develop Capabilities",
        "id": "T1587",
        "link": "https://attack.mitre.org/techniques/T1587",
        "description": "Adversaries may build capabilities that can be used during targeting. Rather than purchasing, freely downloading, or stealing capabilities, adversaries may develop their own capabilities in-house. This is the process of identifying development requirements and building solutions such as malware, exploits, and self-signed certificates. Adversaries may develop capabilities to support their operations throughout numerous phases of the adversary lifecycle.",
        "sub-techniques": [
            {
                "sub-technique": "Malware",
                "id": "T1587.001",
                "link": "https://attack.mitre.org/techniques/T1587/001",
                "description": "Adversaries may develop malware and malware components that can be used during targeting. Building malicious software can include the development of payloads, droppers, post-compromise tools, backdoors (including backdoored images), packers, C2 protocols, and the creation of infected removable media. Adversaries may develop malware to support their operations, creating a means for maintaining control of remote machines, evading defenses, and executing post-compromise behaviors."
            },
            {
                "sub-technique": "Digital Certificates",
                "id": "T1587.003",
                "link": "https://attack.mitre.org/techniques/T1587/003",
                "description": "Adversaries may create self-signed SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are designed to instill trust. They include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate with its owner. In the case of self-signing, digital certificates will lack the element of trust associated with the signature of a third-party certificate authority (CA)."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Pre-compromise",
                "id": "M1056",
                "link": "https://attack.mitre.org/mitigations/M1056",
                "description": "This category is used for any applicable mitigation activities that apply to techniques occurring before an adversary gains Initial Access, such as Reconnaissance and Resource Development techniques."
            }
        ]
    },
    {
        "technique": "Establish Accounts",
        "id": "T1585",
        "link": "https://attack.mitre.org/techniques/T1585",
        "description": "Adversaries may create and cultivate accounts with services that can be used during targeting. Adversaries can create accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations. This development could be applied to social media, website, or other publicly available information that could be referenced and scrutinized for legitimacy over the course of an operation using that persona or identity.",
        "sub-techniques": [
            {
                "sub-technique": "Social Media Accounts",
                "id": "T1585.001",
                "link": "https://attack.mitre.org/techniques/T1585/001",
                "description": "Adversaries may create and cultivate social media accounts that can be used during targeting. Adversaries can create social media accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations."
            },
            {
                "sub-technique": "Cloud Accounts",
                "id": "T1585.003",
                "link": "https://attack.mitre.org/techniques/T1585/003",
                "description": "Adversaries may create accounts with cloud providers that can be used during targeting. Adversaries can use cloud accounts to further their operations, including leveraging cloud storage services such as Dropbox, MEGA, Microsoft OneDrive, or AWS S3 buckets for Exfiltration to Cloud Storage or to Upload Tools. Cloud accounts can also be used in the acquisition of infrastructure, such as Virtual Private Servers or Serverless infrastructure. Establishing cloud accounts may allow adversaries to develop sophisticated capabilities without managing their own servers."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Pre-compromise",
                "id": "M1056",
                "link": "https://attack.mitre.org/mitigations/M1056",
                "description": "This category is used for any applicable mitigation activities that apply to techniques occurring before an adversary gains Initial Access, such as Reconnaissance and Resource Development techniques."
            }
        ]
    },
    {
        "technique": "Obtain Capabilities",
        "id": "T1588",
        "link": "https://attack.mitre.org/techniques/T1588",
        "description": "Adversaries may buy and/or steal capabilities that can be used during targeting. Rather than developing their own capabilities in-house, adversaries may purchase, freely download, or steal them. Activities may include the acquisition of malware, software (including licenses), exploits, certificates, and information relating to vulnerabilities. Adversaries may obtain capabilities to support their operations throughout numerous phases of the adversary lifecycle.",
        "sub-techniques": [
            {
                "sub-technique": "Malware",
                "id": "T1588.001",
                "link": "https://attack.mitre.org/techniques/T1588/001",
                "description": "Adversaries may buy, steal, or download malware that can be used during targeting. Malicious software can include payloads, droppers, post-compromise tools, backdoors, packers, and C2 protocols. Adversaries may acquire malware to support their operations, obtaining a means for maintaining control of remote machines, evading defenses, and executing post-compromise behaviors."
            },
            {
                "sub-technique": "Code Signing Certificates",
                "id": "T1588.003",
                "link": "https://attack.mitre.org/techniques/T1588/003",
                "description": "Adversaries may buy and/or steal code signing certificates that can be used during targeting. Code signing is the process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered or corrupted. Code signing provides a level of authenticity for a program from the developer and a guarantee that the program has not been tampered with. Users and/or security tools may trust a signed piece of code more than an unsigned piece of code even if they don't know who issued the certificate or who the author is."
            },
            {
                "sub-technique": "Exploits",
                "id": "T1588.005",
                "link": "https://attack.mitre.org/techniques/T1588/005",
                "description": "Adversaries may buy, steal, or download exploits that can be used during targeting. An exploit takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software. Rather than developing their own exploits, an adversary may find/modify exploits from online or purchase them from exploit vendors."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Pre-compromise",
                "id": "M1056",
                "link": "https://attack.mitre.org/mitigations/M1056",
                "description": "This category is used for any applicable mitigation activities that apply to techniques occurring before an adversary gains Initial Access, such as Reconnaissance and Resource Development techniques."
            }
        ]
    },
    {
        "technique": "Stage Capabilities",
        "id": "T1608",
        "link": "https://attack.mitre.org/techniques/T1608",
        "description": "Adversaries may upload, install, or otherwise set up capabilities that can be used during targeting. To support their operations, an adversary may need to take capabilities they developed (Develop Capabilities) or obtained (Obtain Capabilities) and stage them on infrastructure under their control. These capabilities may be staged on infrastructure that was previously purchased/rented by the adversary (Acquire Infrastructure) or was otherwise compromised by them (Compromise Infrastructure). Capabilities may also be staged on web services, such as GitHub or Pastebin, or on Platform-as-a-Service (PaaS) offerings that enable users to easily provision applications.",
        "sub-techniques": [
            {
                "sub-technique": "Upload Malware",
                "id": "T1608.001",
                "link": "https://attack.mitre.org/techniques/T1608/001",
                "description": "Adversaries may upload malware to third-party or adversary controlled infrastructure to make it accessible during targeting. Malicious software can include payloads, droppers, post-compromise tools, backdoors, and a variety of other malicious content. Adversaries may upload malware to support their operations, such as making a payload available to a victim network to enable Ingress Tool Transfer by placing it on an Internet accessible web server."
            },
            {
                "sub-technique": "Install Digital Certificate",
                "id": "T1608.003",
                "link": "https://attack.mitre.org/techniques/T1608/003",
                "description": "Adversaries may install SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are files that can be installed on servers to enable secure communications between systems. Digital certificates include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate securely with its owner. Certificates can be uploaded to a server, then the server can be configured to use the certificate to enable encrypted communication with it."
            },
            {
                "sub-technique": "Link Target",
                "id": "T1608.005",
                "link": "https://attack.mitre.org/techniques/T1608/005",
                "description": "Adversaries may put in place resources that are referenced by a link that can be used during targeting. An adversary may rely upon a user clicking a malicious link in order to divulge information (including credentials) or to gain execution, as in Malicious Link. Links can be used for spearphishing, such as sending an email accompanied by social engineering text to coax the user to actively click or copy and paste a URL into a browser. Prior to a phish for information (as in Spearphishing Link) or a phish to gain initial access to a system (as in Spearphishing Link), an adversary must set up the resources for a link target for the spearphishing link."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Pre-compromise",
                "id": "M1056",
                "link": "https://attack.mitre.org/mitigations/M1056",
                "description": "This category is used for any applicable mitigation activities that apply to techniques occurring before an adversary gains Initial Access, such as Reconnaissance and Resource Development techniques."
            }
        ]
    }
]

initial_access = [
    {
        "technique": "Drive-by Compromise",
        "id": "T1189",
        "link": "https://attack.mitre.org/techniques/T1189",
        "description": "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. With this technique, the user's web browser is typically targeted for exploitation, but adversaries may also use compromised websites for non-exploitation behavior such as acquiring Application Access Token.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Application Isolation and Sandboxing",
                "id": "M1048",
                "link": "https://attack.mitre.org/mitigations/M1048",
                "description": "Restrict execution of code to a virtual environment on or in transit to an endpoint system."
            },
            {
                "mitigation": "Exploit Protection",
                "id": "M1050",
                "link": "https://attack.mitre.org/mitigations/M1050",
                "description": "Use capabilities to detect and block conditions that may lead to or be indicative of a software exploit occurring."
            },
            {
                "mitigation": "Restrict Web-Based Content",
                "id": "M1021",
                "link": "https://attack.mitre.org/mitigations/M1021",
                "description": "Restrict use of certain websites, block downloads/attachments, block Javascript, restrict browser extensions, etc."
            },
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            }
        ]
    },
    {
        "technique": "Exploit Public-Facing Application",
        "id": "T1190",
        "link": "https://attack.mitre.org/techniques/T1190",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Application Isolation and Sandboxing",
                "id": "M1048",
                "link": "https://attack.mitre.org/mitigations/M1048",
                "description": "Restrict execution of code to a virtual environment on or in transit to an endpoint system."
            },
            {
                "mitigation": "Exploit Protection",
                "id": "M1050",
                "link": "https://attack.mitre.org/mitigations/M1050",
                "description": "Use capabilities to detect and block conditions that may lead to or be indicative of a software exploit occurring."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            },
            {
                "mitigation": "Vulnerability Scanning",
                "id": "M1016",
                "link": "https://attack.mitre.org/mitigations/M1016",
                "description": "Vulnerability scanning is used to find potentially exploitable software vulnerabilities to remediate them."
            }
        ]
    },
    {
        "technique": "External Remote Services",
        "id": "T1133",
        "link": "https://attack.mitre.org/techniques/T1133",
        "description": "Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as Windows Remote Management and VNC can also be used externally.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Limit Access to Resource Over Network",
                "id": "M1035",
                "link": "https://attack.mitre.org/mitigations/M1035",
                "description": "Prevent access to file shares, remote access to systems, unnecessary services. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc."
            },
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            }
        ]
    },
    {
        "technique": "Hardware Additions",
        "id": "T1200",
        "link": "https://attack.mitre.org/techniques/T1200",
        "description": "Adversaries may introduce computer accessories, networking hardware, or other computing devices into a system or network that can be used as a vector to gain access. Rather than just connecting and distributing payloads via removable storage (i.e. Replication Through Removable Media), more robust hardware additions can be used to introduce new functionalities and/or features into a system that can then be abused.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Limit Access to Resource Over Network",
                "id": "M1035",
                "link": "https://attack.mitre.org/mitigations/M1035",
                "description": "Prevent access to file shares, remote access to systems, unnecessary services. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc."
            },
            {
                "mitigation": "Limit Hardware Installation",
                "id": "M1034",
                "link": "https://attack.mitre.org/mitigations/M1034",
                "description": "Block users or groups from installing or using unapproved hardware on systems, including USB devices."
            }
        ]
    },
    {
        "technique": "Phishing",
        "id": "T1566",
        "link": "https://attack.mitre.org/techniques/T1566",
        "description": "Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary. More generally, adversaries can conduct non-targeted phishing, such as in mass malware spam campaigns.",
        "sub-techniques": [
            {
                "sub-technique": "Spearphishing Attachment",
                "id": "T1566.001",
                "link": "https://attack.mitre.org/techniques/T1566/001",
                "description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon User Execution to gain execution. Spearphishing may also involve social engineering techniques, such as posing as a trusted source."
            },
            {
                "sub-technique": "Spearphishing via Service",
                "id": "T1566.003",
                "link": "https://attack.mitre.org/techniques/T1566/003",
                "description": "Adversaries may send spearphishing messages via third-party services in an attempt to gain access to victim systems. Spearphishing via service is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of third party services rather than directly via enterprise email channels."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Antivirus/Antimalware",
                "id": "M1049",
                "link": "https://attack.mitre.org/mitigations/M1049",
                "description": "Use signatures or heuristics to detect malicious software."
            },
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            },
            {
                "mitigation": "Restrict Web-Based Content",
                "id": "M1021",
                "link": "https://attack.mitre.org/mitigations/M1021",
                "description": "Restrict use of certain websites, block downloads/attachments, block Javascript, restrict browser extensions, etc."
            },
            {
                "mitigation": "Software Configuration",
                "id": "M1054",
                "link": "https://attack.mitre.org/mitigations/M1054",
                "description": "Implement configuration changes to software (other than the operating system) to mitigate security risks associated to how the software operates."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    },
    {
        "technique": "Replication Through Removable Media",
        "id": "T1091",
        "link": "https://attack.mitre.org/techniques/T1091",
        "description": "Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes. In the case of Lateral Movement, this may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system. In the case of Initial Access, this may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Limit Hardware Installation",
                "id": "M1034",
                "link": "https://attack.mitre.org/mitigations/M1034",
                "description": "Block users or groups from installing or using unapproved hardware on systems, including USB devices."
            }
        ]
    },
    {
        "technique": "Supply Chain Compromise",
        "id": "T1195",
        "link": "https://attack.mitre.org/techniques/T1195",
        "description": "Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.",
        "sub-techniques": [
            {
                "sub-technique": "Compromise Software Dependencies and Development Tools",
                "id": "T1195.001",
                "link": "https://attack.mitre.org/techniques/T1195/001",
                "description": "Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise. Applications often depend on external software to function properly. Popular open source projects that are used as dependencies in many applications may be targeted as a means to add malicious code to users of the dependency."
            },
            {
                "sub-technique": "Compromise Hardware Supply Chain",
                "id": "T1195.003",
                "link": "https://attack.mitre.org/techniques/T1195/003",
                "description": "Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise. By modifying hardware or firmware in the supply chain, adversaries can insert a backdoor into consumer networks that may be difficult to detect and give the adversary a high degree of control over the system. Hardware backdoors may be inserted into various devices, such as servers, workstations, network infrastructure, or peripherals."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            },
            {
                "mitigation": "Vulnerability Scanning",
                "id": "M1016",
                "link": "https://attack.mitre.org/mitigations/M1016",
                "description": "Vulnerability scanning is used to find potentially exploitable software vulnerabilities to remediate them."
            }
        ]
    },
    {
        "technique": "Trusted Relationship",
        "id": "T1199",
        "link": "https://attack.mitre.org/techniques/T1199",
        "description": "Adversaries may breach or otherwise leverage organizations who have access to intended victims. Access through trusted third party relationship abuses an existing connection that may not be protected or receives less scrutiny than standard mechanisms of gaining access to a network.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Valid Accounts",
        "id": "T1078",
        "link": "https://attack.mitre.org/techniques/T1078",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access, network devices, and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.",
        "sub-techniques": [
            {
                "sub-technique": "Default Accounts",
                "id": "T1078.001",
                "link": "https://attack.mitre.org/techniques/T1078/001",
                "description": "Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems. Default accounts also include default factory/provider set accounts on other types of systems, software, or devices, including the root user account in AWS and the default service account in Kubernetes."
            },
            {
                "sub-technique": "Local Accounts",
                "id": "T1078.003",
                "link": "https://attack.mitre.org/techniques/T1078/003",
                "description": "Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Account Use Policies",
                "id": "M1036",
                "link": "https://attack.mitre.org/mitigations/M1036",
                "description": "Configure features related to account use like login attempt lockouts, specific login times, etc."
            },
            {
                "mitigation": "Active Directory Configuration",
                "id": "M1015",
                "link": "https://attack.mitre.org/mitigations/M1015",
                "description": "Configure Active Directory to prevent use of certain techniques; use SID Filtering, etc."
            },
            {
                "mitigation": "Application Developer Guidance",
                "id": "M1013",
                "link": "https://attack.mitre.org/mitigations/M1013",
                "description": "This mitigation describes any guidance or training given to developers of applications to avoid introducing security weaknesses that an adversary may be able to take advantage of."
            },
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    }
]

execution = [
    {
        "technique": "Cloud Administration Command",
        "id": "T1651",
        "link": "https://attack.mitre.org/techniques/T1651",
        "description": "Adversaries may abuse cloud management services to execute commands within virtual machines or hybrid-joined devices. Resources such as AWS Systems Manager, Azure RunCommand, and Runbooks allow users to remotely run scripts in virtual machines by leveraging installed virtual machine agents. Similarly, in Azure AD environments, Microsoft Endpoint Manager allows Global or Intune Administrators to run scripts as SYSTEM on on-premises devices joined to the Azure AD.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            }
        ]
    },
    {
        "technique": "Command and Scripting Interpreter",
        "id": "T1059",
        "link": "https://attack.mitre.org/techniques/T1059",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of Unix Shell while Windows installations include the Windows Command Shell and PowerShell.",
        "sub-techniques": [
            {
                "sub-technique": "PowerShell",
                "id": "T1059.001",
                "link": "https://attack.mitre.org/techniques/T1059/001",
                "description": "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer (though administrator permissions are required to use PowerShell to connect to remote systems)."
            },
            {
                "sub-technique": "Windows Command Shell",
                "id": "T1059.003",
                "link": "https://attack.mitre.org/techniques/T1059/003",
                "description": "Adversaries may abuse the Windows command shell for execution. The Windows command shell (cmd) is the primary command prompt on Windows systems. The Windows command prompt can be used to control almost any aspect of a system, with various permission levels required for different subsets of commands. The command prompt can be invoked remotely via Remote Services such as SSH."
            },
            {
                "sub-technique": "Visual Basic",
                "id": "T1059.005",
                "link": "https://attack.mitre.org/techniques/T1059/005",
                "description": "Adversaries may abuse Visual Basic (VB) for execution. VB is a programming language created by Microsoft with interoperability with many Windows technologies such as Component Object Model and the Native API through the Windows API. Although tagged as legacy with no planned future evolutions, VB is integrated and supported in the .NET Framework and cross-platform .NET Core."
            },
            {
                "sub-technique": "JavaScript",
                "id": "T1059.007",
                "link": "https://attack.mitre.org/techniques/T1059/007",
                "description": "Adversaries may abuse various implementations of JavaScript for execution. JavaScript (JS) is a platform-independent scripting language (compiled just-in-time at runtime) commonly associated with scripts in webpages, though JS can be executed in runtime environments outside the browser."
            },
            {
                "sub-technique": "Cloud API",
                "id": "T1059.009",
                "link": "https://attack.mitre.org/techniques/T1059/009",
                "description": "Adversaries may abuse cloud APIs to execute malicious commands. APIs available in cloud environments provide various functionalities and are a feature-rich method for programmatic access to nearly all aspects of a tenant. These APIs may be utilized through various methods such as command line interpreters (CLIs), in-browser Cloud Shells, PowerShell modules like Azure for PowerShell, or software developer kits (SDKs) available for languages such as Python."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Antivirus/Antimalware",
                "id": "M1049",
                "link": "https://attack.mitre.org/mitigations/M1049",
                "description": "Use signatures or heuristics to detect malicious software."
            },
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Code Signing",
                "id": "M1045",
                "link": "https://attack.mitre.org/mitigations/M1045",
                "description": "Enforce binary and application integrity with digital signature verification to prevent untrusted code from executing."
            },
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Restrict Web-Based Content",
                "id": "M1021",
                "link": "https://attack.mitre.org/mitigations/M1021",
                "description": "Restrict use of certain websites, block downloads/attachments, block Javascript, restrict browser extensions, etc."
            }
        ]
    },
    {
        "technique": "Container Administration Command",
        "id": "T1609",
        "link": "https://attack.mitre.org/techniques/T1609",
        "description": "Adversaries may abuse a container administration service to execute commands within a container. A container administration service such as the Docker daemon, the Kubernetes API server, or the kubelet may allow remote management of containers within an environment.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            },
            {
                "mitigation": "Limit Access to Resource Over Network",
                "id": "M1035",
                "link": "https://attack.mitre.org/mitigations/M1035",
                "description": "Prevent access to file shares, remote access to systems, unnecessary services. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Deploy Container",
        "id": "T1610",
        "link": "https://attack.mitre.org/techniques/T1610",
        "description": "Adversaries may deploy a container into an environment to facilitate execution or evade defenses. In some cases, adversaries may deploy a new container to execute processes associated with a particular image or deployment, such as processes that execute or download malware. In others, an adversary may deploy a new container configured without network rules, user limitations, etc. to bypass existing defenses within the environment.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Limit Access to Resource Over Network",
                "id": "M1035",
                "link": "https://attack.mitre.org/mitigations/M1035",
                "description": "Prevent access to file shares, remote access to systems, unnecessary services. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Exploitation for Client Execution",
        "id": "T1203",
        "link": "https://attack.mitre.org/techniques/T1203",
        "description": "Adversaries may exploit software vulnerabilities in client applications to execute code. Vulnerabilities can exist in software due to unsecure coding practices that can lead to unanticipated behavior. Adversaries can take advantage of certain vulnerabilities through targeted exploitation for the purpose of arbitrary code execution. Oftentimes the most valuable exploits to an offensive toolkit are those that can be used to obtain code execution on a remote system because they can be used to gain access to that system. Users will expect to see files related to the applications they commonly used to do work, so they are a useful target for exploit research and development because of their high utility.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Application Isolation and Sandboxing",
                "id": "M1048",
                "link": "https://attack.mitre.org/mitigations/M1048",
                "description": "Restrict execution of code to a virtual environment on or in transit to an endpoint system."
            },
            {
                "mitigation": "Exploit Protection",
                "id": "M1050",
                "link": "https://attack.mitre.org/mitigations/M1050",
                "description": "Use capabilities to detect and block conditions that may lead to or be indicative of a software exploit occurring."
            }
        ]
    },
    {
        "technique": "Inter-Process Communication",
        "id": "T1559",
        "link": "https://attack.mitre.org/techniques/T1559",
        "description": "Adversaries may abuse inter-process communication (IPC) mechanisms for local code or command execution. IPC is typically used by processes to share data, communicate with each other, or synchronize execution. IPC is also commonly used to avoid situations such as deadlocks, which occurs when processes are stuck in a cyclic waiting pattern.",
        "sub-techniques": [
            {
                "sub-technique": "Component Object Model",
                "id": "T1559.001",
                "link": "https://attack.mitre.org/techniques/T1559/001",
                "description": "Adversaries may use the Windows Component Object Model (COM) for local code execution. COM is an inter-process communication (IPC) component of the native Windows application programming interface (API) that enables interaction between software objects, or executable code that implements one or more interfaces. Through COM, a client object can call methods of server objects, which are typically binary Dynamic Link Libraries (DLL) or executables (EXE). Remote COM execution is facilitated by Remote Services such as  Distributed Component Object Model (DCOM)."
            },
            {
                "sub-technique": "XPC Services",
                "id": "T1559.003",
                "link": "https://attack.mitre.org/techniques/T1559/003",
                "description": "Adversaries can provide malicious content to an XPC service daemon for local code execution. macOS uses XPC services for basic inter-process communication between various processes, such as between the XPC Service daemon and third-party application privileged helper tools. Applications can send messages to the XPC Service daemon, which runs as root, using the low-level XPC Service C API or the high level NSXPCConnection API in order to handle tasks that require elevated privileges (such as network connections). Applications are responsible for providing the protocol definition which serves as a blueprint of the XPC services. Developers typically use XPC Services to provide applications stability and privilege separation between the application client and the daemon."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Application Developer Guidance",
                "id": "M1013",
                "link": "https://attack.mitre.org/mitigations/M1013",
                "description": "This mitigation describes any guidance or training given to developers of applications to avoid introducing security weaknesses that an adversary may be able to take advantage of."
            },
            {
                "mitigation": "Application Isolation and Sandboxing",
                "id": "M1048",
                "link": "https://attack.mitre.org/mitigations/M1048",
                "description": "Restrict execution of code to a virtual environment on or in transit to an endpoint system."
            },
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Software Configuration",
                "id": "M1054",
                "link": "https://attack.mitre.org/mitigations/M1054",
                "description": "Implement configuration changes to software (other than the operating system) to mitigate security risks associated to how the software operates."
            }
        ]
    },
    {
        "technique": "Native API",
        "id": "T1106",
        "link": "https://attack.mitre.org/techniques/T1106",
        "description": "Adversaries may interact with the native OS application programming interface (API) to execute behaviors. Native APIs provide a controlled means of calling low-level OS services within the kernel, such as those involving hardware/devices, memory, and processes. These native APIs are leveraged by the OS during system boot (when other system components are not yet initialized) as well as carrying out tasks and requests during routine operations.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            }
        ]
    },
    {
        "technique": "Scheduled Task/Job",
        "id": "T1053",
        "link": "https://attack.mitre.org/techniques/T1053",
        "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically may require being a member of an admin or otherwise privileged group on the remote system.",
        "sub-techniques": [
            {
                "sub-technique": "At",
                "id": "T1053.002",
                "link": "https://attack.mitre.org/techniques/T1053/002",
                "description": "Adversaries may abuse the at utility to perform task scheduling for initial or recurring execution of malicious code. The at utility exists as an executable within Windows, Linux, and macOS for scheduling tasks at a specified time and date. Although deprecated in favor of Scheduled Task's schtasks in Windows environments, using at requires that the Task Scheduler service be running, and the user to be logged on as a member of the local Administrators group."
            },
            {
                "sub-technique": "Scheduled Task",
                "id": "T1053.005",
                "link": "https://attack.mitre.org/techniques/T1053/005",
                "description": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The schtasks utility can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel. In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library to create a scheduled task."
            },
            {
                "sub-technique": "Container Orchestration Job",
                "id": "T1053.007",
                "link": "https://attack.mitre.org/techniques/T1053/007",
                "description": "Adversaries may abuse task scheduling functionality provided by container orchestration tools such as Kubernetes to schedule deployment of containers configured to execute malicious code. Container orchestration jobs run these automated tasks at a specific date and time, similar to cron jobs on a Linux system. Deployments of this type can also be configured to maintain a quantity of containers over time, automating the process of maintaining persistence within a cluster."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Serverless Execution",
        "id": "T1648",
        "link": "https://attack.mitre.org/techniques/T1648",
        "description": "Adversaries may abuse serverless computing, integration, and automation services to execute arbitrary code in cloud environments. Many cloud providers offer a variety of serverless resources, including compute engines, application integration services, and web servers.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Shared Modules",
        "id": "T1129",
        "link": "https://attack.mitre.org/techniques/T1129",
        "description": "Adversaries may execute malicious payloads via loading shared modules. The Windows module loader can be instructed to load DLLs from arbitrary local paths and arbitrary Universal Naming Convention (UNC) network paths. This functionality resides in NTDLL.dll and is part of the Windows Native API which is called from functions like CreateProcess, LoadLibrary, etc. of the Win32 API.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            }
        ]
    },
    {
        "technique": "Software Deployment Tools",
        "id": "T1072",
        "link": "https://attack.mitre.org/techniques/T1072",
        "description": "Adversaries may gain access to and use third-party software suites installed within an enterprise network, such as administration, monitoring, and deployment systems, to move laterally through the network. Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, HBSS, Altiris, etc.).",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Active Directory Configuration",
                "id": "M1015",
                "link": "https://attack.mitre.org/mitigations/M1015",
                "description": "Configure Active Directory to prevent use of certain techniques; use SID Filtering, etc."
            },
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            },
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Remote Data Storage",
                "id": "M1029",
                "link": "https://attack.mitre.org/mitigations/M1029",
                "description": "Use remote security log and sensitive file storage where access can be controlled better to prevent exposure of intrusion detection log data or sensitive information."
            },
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    },
    {
        "technique": "System Services",
        "id": "T1569",
        "link": "https://attack.mitre.org/techniques/T1569",
        "description": "Adversaries may abuse system services or daemons to execute commands or programs. Adversaries can execute malicious content by interacting with or creating services either locally or remotely. Many services are set to run at boot, which can aid in achieving persistence (Create or Modify System Process), but adversaries can also abuse services for one-time or temporary execution.",
        "sub-techniques": [
            {
                "sub-technique": "Launchctl",
                "id": "T1569.001",
                "link": "https://attack.mitre.org/techniques/T1569/001",
                "description": "Adversaries may abuse launchctl to execute commands or programs. Launchctl interfaces with launchd, the service management framework for macOS. Launchctl supports taking subcommands on the command-line, interactively, or even redirected from standard input."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "User Execution",
        "id": "T1204",
        "link": "https://attack.mitre.org/techniques/T1204",
        "description": "An adversary may rely upon specific actions by a user in order to gain execution. Users may be subjected to social engineering to get them to execute malicious code by, for example, opening a malicious document file or link. These user actions will typically be observed as follow-on behavior from forms of Phishing.",
        "sub-techniques": [
            {
                "sub-technique": "Malicious Link",
                "id": "T1204.001",
                "link": "https://attack.mitre.org/techniques/T1204/001",
                "description": "An adversary may rely upon a user clicking a malicious link in order to gain execution. Users may be subjected to social engineering to get them to click on a link that will lead to code execution. This user action will typically be observed as follow-on behavior from Spearphishing Link. Clicking on a link may also lead to other execution techniques such as exploitation of a browser or application vulnerability via Exploitation for Client Execution. Links may also lead users to download files that require execution via Malicious File."
            },
            {
                "sub-technique": "Malicious Image",
                "id": "T1204.003",
                "link": "https://attack.mitre.org/techniques/T1204/003",
                "description": "Adversaries may rely on a user running a malicious image to facilitate execution. Amazon Web Services (AWS) Amazon Machine Images (AMIs), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be backdoored. Backdoored images may be uploaded to a public repository via Upload Malware, and users may then download and deploy an instance or container from the image without realizing the image is malicious, thus bypassing techniques that specifically achieve Initial Access. This can lead to the execution of malicious code, such as code that executes cryptocurrency mining, in the instance or container."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            },
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            },
            {
                "mitigation": "Restrict Web-Based Content",
                "id": "M1021",
                "link": "https://attack.mitre.org/mitigations/M1021",
                "description": "Restrict use of certain websites, block downloads/attachments, block Javascript, restrict browser extensions, etc."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    },
    {
        "technique": "Windows Management Instrumentation",
        "id": "T1047",
        "link": "https://attack.mitre.org/techniques/T1047",
        "description": "Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads. WMI is an administration feature that provides a uniform environment to access Windows system components. The WMI service enables both local and remote access, though the latter is facilitated by Remote Services such as Distributed Component Object Model (DCOM) and Windows Remote Management (WinRM). Remote WMI over DCOM operates using port 135, whereas WMI over WinRM operates over port 5985 when using HTTP and 5986 for HTTPS.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    }
]

persistence = [
    {
        "technique": "Account Manipulation",
        "id": "T1098",
        "link": "https://attack.mitre.org/techniques/T1098",
        "description": "Adversaries may manipulate accounts to maintain access to victim systems. Account manipulation may consist of any action that preserves adversary access to a compromised account, such as modifying credentials or permission groups. These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials.",
        "sub-techniques": [
            {
                "sub-technique": "Additional Cloud Credentials",
                "id": "T1098.001",
                "link": "https://attack.mitre.org/techniques/T1098/001",
                "description": "Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment."
            },
            {
                "sub-technique": "Additional Cloud Roles",
                "id": "T1098.003",
                "link": "https://attack.mitre.org/techniques/T1098/003",
                "description": "An adversary may add additional roles or permissions to an adversary-controlled cloud account to maintain persistent access to a tenant. For example, adversaries may update IAM policies in cloud-based environments or add a new global administrator in Office 365 environments. With sufficient permissions, a compromised account can gain almost unlimited access to data and settings (including the ability to reset the passwords of other admins)."
            },
            {
                "sub-technique": "Device Registration",
                "id": "T1098.005",
                "link": "https://attack.mitre.org/techniques/T1098/005",
                "description": "Adversaries may register a device to an adversary-controlled account. Devices may be registered in a multifactor authentication (MFA) system, which handles authentication to the network, or in a device management system, which handles device access and compliance."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "BITS Jobs",
        "id": "T1197",
        "link": "https://attack.mitre.org/techniques/T1197",
        "description": "Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM). BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Boot or Logon Autostart Execution",
        "id": "T1547",
        "link": "https://attack.mitre.org/techniques/T1547",
        "description": "Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon. These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel.",
        "sub-techniques": [
            {
                "sub-technique": "Registry Run Keys / Startup Folder",
                "id": "T1547.001",
                "link": "https://attack.mitre.org/techniques/T1547/001",
                "description": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the \"run keys\" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. These programs will be executed under the context of the user and will have the account's associated permissions level."
            },
            {
                "sub-technique": "Time Providers",
                "id": "T1547.003",
                "link": "https://attack.mitre.org/techniques/T1547/003",
                "description": "Adversaries may abuse time providers to execute DLLs when the system boots. The Windows Time service (W32Time) enables time synchronization across and within domains. W32Time time providers are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients."
            },
            {
                "sub-technique": "Security Support Provider",
                "id": "T1547.005",
                "link": "https://attack.mitre.org/techniques/T1547/005",
                "description": "Adversaries may abuse security support providers (SSPs) to execute DLLs when the system boots. Windows SSP DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs."
            },
            {
                "sub-technique": "Re-opened Applications",
                "id": "T1547.007",
                "link": "https://attack.mitre.org/techniques/T1547/007",
                "description": "Adversaries may modify plist files to automatically run an application when a user logs in. When a user logs out or restarts via the macOS Graphical User Interface (GUI), a prompt is provided to the user with a checkbox to \"Reopen windows when logging back in\". When selected, all applications currently open are added to a property list file named com.apple.loginwindow.[UUID].plist within the ~/Library/Preferences/ByHost directory. Applications listed in this file are automatically reopened upon the user’s next logon."
            },
            {
                "sub-technique": "Shortcut Modification",
                "id": "T1547.009",
                "link": "https://attack.mitre.org/techniques/T1547/009",
                "description": "Adversaries may create or modify shortcuts that can execute a program during system boot or user login. Shortcuts or symbolic links are used to reference other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process."
            },
            {
                "sub-technique": "Print Processors",
                "id": "T1547.012",
                "link": "https://attack.mitre.org/techniques/T1547/012",
                "description": "Adversaries may abuse print processors to run malicious DLLs during system boot for persistence and/or privilege escalation. Print processors are DLLs that are loaded by the print spooler service, spoolsv.exe, during boot."
            },
            {
                "sub-technique": "Active Setup",
                "id": "T1547.014",
                "link": "https://attack.mitre.org/techniques/T1547/014",
                "description": "Adversaries may achieve persistence by adding a Registry key to the Active Setup of the local machine. Active Setup is a Windows mechanism that is used to execute programs when a user logs in. The value stored in the Registry key will be executed after a user logs into the computer. These programs will be executed under the context of the user and will have the account's associated permissions level."
            }
        ],
        "mitigations": []
    },
    {
        "technique": "Boot or Logon Initialization Scripts",
        "id": "T1037",
        "link": "https://attack.mitre.org/techniques/T1037",
        "description": "Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence. Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating system and whether applied locally or remotely.",
        "sub-techniques": [
            {
                "sub-technique": "Logon Script (Windows)",
                "id": "T1037.001",
                "link": "https://attack.mitre.org/techniques/T1037/001",
                "description": "Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence. Windows allows logon scripts to be run whenever a specific user or group of users log into a system. This is done via adding a path to a script to the HKCU\\Environment\\UserInitMprLogonScript Registry key."
            },
            {
                "sub-technique": "Network Logon Script",
                "id": "T1037.003",
                "link": "https://attack.mitre.org/techniques/T1037/003",
                "description": "Adversaries may use network logon scripts automatically executed at logon initialization to establish persistence. Network logon scripts can be assigned using Active Directory or Group Policy Objects. These logon scripts run with the privileges of the user they are assigned to. Depending on the systems within the network, initializing one of these scripts could apply to more than one or potentially all systems."
            },
            {
                "sub-technique": "Startup Items",
                "id": "T1037.005",
                "link": "https://attack.mitre.org/techniques/T1037/005",
                "description": "Adversaries may use startup items automatically executed at boot initialization to establish persistence. Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            },
            {
                "mitigation": "Restrict Registry Permissions",
                "id": "M1024",
                "link": "https://attack.mitre.org/mitigations/M1024",
                "description": "Restrict the ability to modify certain hives or keys in the Windows Registry."
            }
        ]
    },
    {
        "technique": "Browser Extensions",
        "id": "T1176",
        "link": "https://attack.mitre.org/techniques/T1176",
        "description": "Adversaries may abuse Internet browser extensions to establish persistent access to victim systems. Browser extensions or plugins are small programs that can add functionality and customize aspects of Internet browsers. They can be installed directly or through a browser's app store and generally have access and permissions to everything that the browser can access.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            },
            {
                "mitigation": "Limit Software Installation",
                "id": "M1033",
                "link": "https://attack.mitre.org/mitigations/M1033",
                "description": "Block users or groups from installing unapproved software."
            },
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    },
    {
        "technique": "Compromise Client Software Binary",
        "id": "T1554",
        "link": "https://attack.mitre.org/techniques/T1554",
        "description": "Adversaries may modify client software binaries to establish persistent access to systems. Client software enables users to access services provided by a server. Common client software types are SSH clients, FTP clients, email clients, and web browsers.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Code Signing",
                "id": "M1045",
                "link": "https://attack.mitre.org/mitigations/M1045",
                "description": "Enforce binary and application integrity with digital signature verification to prevent untrusted code from executing."
            }
        ]
    },
    {
        "technique": "Create Account",
        "id": "T1136",
        "link": "https://attack.mitre.org/techniques/T1136",
        "description": "Adversaries may create an account to maintain access to victim systems. With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.",
        "sub-techniques": [
            {
                "sub-technique": "Local Account",
                "id": "T1136.001",
                "link": "https://attack.mitre.org/techniques/T1136/001",
                "description": "Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service. With a sufficient level of access, the net user /add command can be used to create a local account. On macOS systems the dscl -create command can be used to create a local account. Local accounts may also be added to network devices, often via common Network Device CLI commands such as username."
            },
            {
                "sub-technique": "Cloud Account",
                "id": "T1136.003",
                "link": "https://attack.mitre.org/techniques/T1136/003",
                "description": "Adversaries may create a cloud account to maintain access to victim systems. With a sufficient level of access, such accounts may be used to establish secondary credentialed access that does not require persistent remote access tools to be deployed on the system."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            }
        ]
    },
    {
        "technique": "Create or Modify System Process",
        "id": "T1543",
        "link": "https://attack.mitre.org/techniques/T1543",
        "description": "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services. On macOS, launchd processes known as Launch Daemon and Launch Agent are run to finish system initialization and load user specific parameters.",
        "sub-techniques": [
            {
                "sub-technique": "Launch Agent",
                "id": "T1543.001",
                "link": "https://attack.mitre.org/techniques/T1543/001",
                "description": "Adversaries may create or modify launch agents to repeatedly execute malicious payloads as part of persistence. When a user logs in, a per-user launchd process is started which loads the parameters for each launch-on-demand user agent from the property list (.plist) file found in /System/Library/LaunchAgents, /Library/LaunchAgents, and ~/Library/LaunchAgents.  Property list files use the Label, ProgramArguments , and RunAtLoad keys to identify the Launch Agent's name, executable location, and execution time. Launch Agents are often installed to perform updates to programs, launch user specified programs at login, or to conduct other developer tasks."
            },
            {
                "sub-technique": "Windows Service",
                "id": "T1543.003",
                "link": "https://attack.mitre.org/techniques/T1543/003",
                "description": "Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions. Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Windows Registry."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Code Signing",
                "id": "M1045",
                "link": "https://attack.mitre.org/mitigations/M1045",
                "description": "Enforce binary and application integrity with digital signature verification to prevent untrusted code from executing."
            },
            {
                "mitigation": "Limit Software Installation",
                "id": "M1033",
                "link": "https://attack.mitre.org/mitigations/M1033",
                "description": "Block users or groups from installing unapproved software."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Event Triggered Execution",
        "id": "T1546",
        "link": "https://attack.mitre.org/techniques/T1546",
        "description": "Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries. Cloud environments may also support various functions and services that monitor and can be invoked in response to specific cloud events.",
        "sub-techniques": [
            {
                "sub-technique": "Change Default File Association",
                "id": "T1546.001",
                "link": "https://attack.mitre.org/techniques/T1546/001",
                "description": "Adversaries may establish persistence by executing malicious content triggered by a file type association. When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened."
            },
            {
                "sub-technique": "Windows Management Instrumentation Event Subscription",
                "id": "T1546.003",
                "link": "https://attack.mitre.org/techniques/T1546/003",
                "description": "Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription. WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Examples of events that may be subscribed to are the wall clock time, user loging, or the computer's uptime."
            },
            {
                "sub-technique": "Trap",
                "id": "T1546.005",
                "link": "https://attack.mitre.org/techniques/T1546/005",
                "description": "Adversaries may establish persistence by executing malicious content triggered by an interrupt signal. The trap command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like ctrl+c and ctrl+d."
            },
            {
                "sub-technique": "Netsh Helper DLL",
                "id": "T1546.007",
                "link": "https://attack.mitre.org/techniques/T1546/007",
                "description": "Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs. Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system. It contains functionality to add helper DLLs for extending functionality of the utility. The paths to registered netsh.exe helper DLLs are entered into the Windows Registry at HKLM\\SOFTWARE\\Microsoft\\Netsh."
            },
            {
                "sub-technique": "AppCert DLLs",
                "id": "T1546.009",
                "link": "https://attack.mitre.org/techniques/T1546/009",
                "description": "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppCert DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs Registry key under HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\ are loaded into every process that calls the ubiquitously used application programming interface (API) functions CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW, CreateProcessWithTokenW, or WinExec."
            },
            {
                "sub-technique": "Application Shimming",
                "id": "T1546.011",
                "link": "https://attack.mitre.org/techniques/T1546/011",
                "description": "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims. The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time. For example, the application shimming feature allows developers to apply fixes to applications (without rewriting code) that were created for Windows XP so that it will work with Windows 10."
            },
            {
                "sub-technique": "PowerShell Profile",
                "id": "T1546.013",
                "link": "https://attack.mitre.org/techniques/T1546/013",
                "description": "Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles. A PowerShell profile  (profile.ps1) is a script that runs when PowerShell starts and can be used as a logon script to customize user environments."
            },
            {
                "sub-technique": "Component Object Model Hijacking",
                "id": "T1546.015",
                "link": "https://attack.mitre.org/techniques/T1546/015",
                "description": "Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects. COM is a system within Windows to enable interaction between software components through the operating system.  References to various COM objects are stored in the Registry."
            }
        ],
        "mitigations": []
    },
    {
        "technique": "External Remote Services",
        "id": "T1133",
        "link": "https://attack.mitre.org/techniques/T1133",
        "description": "Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as Windows Remote Management and VNC can also be used externally.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Limit Access to Resource Over Network",
                "id": "M1035",
                "link": "https://attack.mitre.org/mitigations/M1035",
                "description": "Prevent access to file shares, remote access to systems, unnecessary services. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc."
            },
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            }
        ]
    },
    {
        "technique": "Hijack Execution Flow",
        "id": "T1574",
        "link": "https://attack.mitre.org/techniques/T1574",
        "description": "Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.",
        "sub-techniques": [
            {
                "sub-technique": "DLL Search Order Hijacking",
                "id": "T1574.001",
                "link": "https://attack.mitre.org/techniques/T1574/001",
                "description": "Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs. Windows systems use a common method to look for required DLLs to load into a program.  Hijacking DLL loads may be for the purpose of establishing persistence as well as elevating privileges and/or evading restrictions on file execution."
            },
            {
                "sub-technique": "Dylib Hijacking",
                "id": "T1574.004",
                "link": "https://attack.mitre.org/techniques/T1574/004",
                "description": "Adversaries may execute their own payloads by placing a malicious dynamic library (dylib) with an expected name in a path a victim application searches at runtime. The dynamic loader will try to find the dylibs based on the sequential order of the search paths. Paths to dylibs may be prefixed with @rpath, which allows developers to use relative paths to specify an array of search paths used at runtime based on the location of the executable.  Additionally, if weak linking is used, such as the LC_LOAD_WEAK_DYLIB function, an application will still execute even if an expected dylib is not present. Weak linking enables developers to run an application on multiple macOS versions as new APIs are added."
            },
            {
                "sub-technique": "Dynamic Linker Hijacking",
                "id": "T1574.006",
                "link": "https://attack.mitre.org/techniques/T1574/006",
                "description": "Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries. During the execution preparation phase of a program, the dynamic linker loads specified absolute paths of shared libraries from environment variables and files, such as LD_PRELOAD on Linux or DYLD_INSERT_LIBRARIES on macOS. Libraries specified in environment variables are loaded first, taking precedence over system libraries with the same function name. These variables are often used by developers to debug binaries without needing to recompile, deconflict mapped symbols, and implement custom functions without changing the original library."
            },
            {
                "sub-technique": "Path Interception by Search Order Hijacking",
                "id": "T1574.008",
                "link": "https://attack.mitre.org/techniques/T1574/008",
                "description": "Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the calling program is located, causing the operating system to launch their malicious software at the request of the calling program."
            },
            {
                "sub-technique": "Services File Permissions Weakness",
                "id": "T1574.010",
                "link": "https://attack.mitre.org/techniques/T1574/010",
                "description": "Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM."
            },
            {
                "sub-technique": "COR_PROFILER",
                "id": "T1574.012",
                "link": "https://attack.mitre.org/techniques/T1574/012",
                "description": "Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the .NET CLR. The COR_PROFILER is a .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR). These profilers are designed to monitor, troubleshoot, and debug managed code executed by the .NET CLR."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Application Developer Guidance",
                "id": "M1013",
                "link": "https://attack.mitre.org/mitigations/M1013",
                "description": "This mitigation describes any guidance or training given to developers of applications to avoid introducing security weaknesses that an adversary may be able to take advantage of."
            },
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            },
            {
                "mitigation": "Restrict Library Loading",
                "id": "M1044",
                "link": "https://attack.mitre.org/mitigations/M1044",
                "description": "Prevent abuse of library loading mechanisms in the operating system and software to load untrusted code by configuring appropriate library loading mechanisms and investigating potential vulnerable software."
            },
            {
                "mitigation": "Restrict Registry Permissions",
                "id": "M1024",
                "link": "https://attack.mitre.org/mitigations/M1024",
                "description": "Restrict the ability to modify certain hives or keys in the Windows Registry."
            },
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            },
            {
                "mitigation": "User Account Control",
                "id": "M1052",
                "link": "https://attack.mitre.org/mitigations/M1052",
                "description": "Configure Windows User Account Control to mitigate risk of adversaries obtaining elevated process access."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Implant Internal Image",
        "id": "T1525",
        "link": "https://attack.mitre.org/techniques/T1525",
        "description": "Adversaries may implant cloud or container images with malicious code to establish persistence after gaining access to an environment. Amazon Web Services (AWS) Amazon Machine Images (AMIs), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be implanted or backdoored. Unlike Upload Malware, this technique focuses on adversaries implanting an image in a registry within a victim’s environment. Depending on how the infrastructure is provisioned, this could provide persistent access if the infrastructure provisioning tool is instructed to always use the latest image.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Code Signing",
                "id": "M1045",
                "link": "https://attack.mitre.org/mitigations/M1045",
                "description": "Enforce binary and application integrity with digital signature verification to prevent untrusted code from executing."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            }
        ]
    },
    {
        "technique": "Modify Authentication Process",
        "id": "T1556",
        "link": "https://attack.mitre.org/techniques/T1556",
        "description": "Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials. By modifying an authentication process, an adversary may be able to authenticate to a service or system without using Valid Accounts.",
        "sub-techniques": [
            {
                "sub-technique": "Domain Controller Authentication",
                "id": "T1556.001",
                "link": "https://attack.mitre.org/techniques/T1556/001",
                "description": "Adversaries may patch the authentication process on a domain controller to bypass the typical authentication mechanisms and enable access to accounts."
            },
            {
                "sub-technique": "Pluggable Authentication Modules",
                "id": "T1556.003",
                "link": "https://attack.mitre.org/techniques/T1556/003",
                "description": "Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts. PAM is a modular system of configuration files, libraries, and executable files which guide authentication for many services. The most common authentication module is pam_unix.so, which retrieves, sets, and verifies account authentication information in /etc/passwd and /etc/shadow."
            },
            {
                "sub-technique": "Reversible Encryption",
                "id": "T1556.005",
                "link": "https://attack.mitre.org/techniques/T1556/005",
                "description": "An adversary may abuse Active Directory authentication encryption properties to gain access to credentials on Windows systems. The AllowReversiblePasswordEncryption property specifies whether reversible password encryption for an account is enabled or disabled. By default this property is disabled (instead storing user credentials as the output of one-way hashing functions) and should not be enabled unless legacy or other software require it."
            },
            {
                "sub-technique": "Hybrid Identity",
                "id": "T1556.007",
                "link": "https://attack.mitre.org/techniques/T1556/007",
                "description": "Adversaries may patch, modify, or otherwise backdoor cloud authentication processes that are tied to on-premises user identities in order to bypass typical authentication mechanisms, access credentials, and enable persistent access to accounts."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            },
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Privileged Process Integrity",
                "id": "M1025",
                "link": "https://attack.mitre.org/mitigations/M1025",
                "description": "Protect processes with high privileges that can be used to interact with critical system components through use of protected process light, anti-process injection defenses, or other process integrity enforcement measures."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            },
            {
                "mitigation": "Restrict Registry Permissions",
                "id": "M1024",
                "link": "https://attack.mitre.org/mitigations/M1024",
                "description": "Restrict the ability to modify certain hives or keys in the Windows Registry."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Office Application Startup",
        "id": "T1137",
        "link": "https://attack.mitre.org/techniques/T1137",
        "description": "Adversaries may leverage Microsoft Office-based applications for persistence between startups. Microsoft Office is a fairly common application suite on Windows-based operating systems within an enterprise network. There are multiple mechanisms that can be used with Office for persistence when an Office-based application is started; this can include the use of Office Template Macros and add-ins.",
        "sub-techniques": [
            {
                "sub-technique": "Office Template Macros",
                "id": "T1137.001",
                "link": "https://attack.mitre.org/techniques/T1137/001",
                "description": "Adversaries may abuse Microsoft Office templates to obtain persistence on a compromised system. Microsoft Office contains templates that are part of common Office applications and are used to customize styles. The base templates within the application are used each time an application starts."
            },
            {
                "sub-technique": "Outlook Forms",
                "id": "T1137.003",
                "link": "https://attack.mitre.org/techniques/T1137/003",
                "description": "Adversaries may abuse Microsoft Outlook forms to obtain persistence on a compromised system. Outlook forms are used as templates for presentation and functionality in Outlook messages. Custom Outlook forms can be created that will execute code when a specifically crafted email is sent by an adversary utilizing the same custom Outlook form."
            },
            {
                "sub-technique": "Outlook Rules",
                "id": "T1137.005",
                "link": "https://attack.mitre.org/techniques/T1137/005",
                "description": "Adversaries may abuse Microsoft Outlook rules to obtain persistence on a compromised system. Outlook rules allow a user to define automated behavior to manage email messages. A benign rule might, for example, automatically move an email to a particular folder in Outlook if it contains specific words from a specific sender. Malicious Outlook rules can be created that can trigger code execution when an adversary sends a specifically crafted email to that user."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Software Configuration",
                "id": "M1054",
                "link": "https://attack.mitre.org/mitigations/M1054",
                "description": "Implement configuration changes to software (other than the operating system) to mitigate security risks associated to how the software operates."
            },
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            }
        ]
    },
    {
        "technique": "Pre-OS Boot",
        "id": "T1542",
        "link": "https://attack.mitre.org/techniques/T1542",
        "description": "Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence on a system. During the booting process of a computer, firmware and various startup services are loaded before the operating system. These programs control flow of execution before the operating system takes control.",
        "sub-techniques": [
            {
                "sub-technique": "System Firmware",
                "id": "T1542.001",
                "link": "https://attack.mitre.org/techniques/T1542/001",
                "description": "Adversaries may modify system firmware to persist on systems.The BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) or Extensible Firmware Interface (EFI) are examples of system firmware that operate as the software interface between the operating system and hardware of a computer."
            },
            {
                "sub-technique": "Bootkit",
                "id": "T1542.003",
                "link": "https://attack.mitre.org/techniques/T1542/003",
                "description": "Adversaries may use bootkits to persist on systems. Bootkits reside at a layer below the operating system and may make it difficult to perform full remediation unless an organization suspects one was used and can act accordingly."
            },
            {
                "sub-technique": "TFTP Boot",
                "id": "T1542.005",
                "link": "https://attack.mitre.org/techniques/T1542/005",
                "description": "Adversaries may abuse netbooting to load an unauthorized network device operating system from a Trivial File Transfer Protocol (TFTP) server. TFTP boot (netbooting) is commonly used by network administrators to load configuration-controlled network device images from a centralized management server. Netbooting is one option in the boot sequence and can be used to centralize, manage, and control device images."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Boot Integrity",
                "id": "M1046",
                "link": "https://attack.mitre.org/mitigations/M1046",
                "description": "Use secure methods to boot a system and verify the integrity of the operating system and loading mechanisms."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            }
        ]
    },
    {
        "technique": "Scheduled Task/Job",
        "id": "T1053",
        "link": "https://attack.mitre.org/techniques/T1053",
        "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically may require being a member of an admin or otherwise privileged group on the remote system.",
        "sub-techniques": [
            {
                "sub-technique": "At",
                "id": "T1053.002",
                "link": "https://attack.mitre.org/techniques/T1053/002",
                "description": "Adversaries may abuse the at utility to perform task scheduling for initial or recurring execution of malicious code. The at utility exists as an executable within Windows, Linux, and macOS for scheduling tasks at a specified time and date. Although deprecated in favor of Scheduled Task's schtasks in Windows environments, using at requires that the Task Scheduler service be running, and the user to be logged on as a member of the local Administrators group."
            },
            {
                "sub-technique": "Scheduled Task",
                "id": "T1053.005",
                "link": "https://attack.mitre.org/techniques/T1053/005",
                "description": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The schtasks utility can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel. In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library to create a scheduled task."
            },
            {
                "sub-technique": "Container Orchestration Job",
                "id": "T1053.007",
                "link": "https://attack.mitre.org/techniques/T1053/007",
                "description": "Adversaries may abuse task scheduling functionality provided by container orchestration tools such as Kubernetes to schedule deployment of containers configured to execute malicious code. Container orchestration jobs run these automated tasks at a specific date and time, similar to cron jobs on a Linux system. Deployments of this type can also be configured to maintain a quantity of containers over time, automating the process of maintaining persistence within a cluster."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Server Software Component",
        "id": "T1505",
        "link": "https://attack.mitre.org/techniques/T1505",
        "description": "Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems. Enterprise server applications may include features that allow developers to write and install software or scripts to extend the functionality of the main application. Adversaries may install malicious components to extend and abuse server applications.",
        "sub-techniques": [
            {
                "sub-technique": "SQL Stored Procedures",
                "id": "T1505.001",
                "link": "https://attack.mitre.org/techniques/T1505/001",
                "description": "Adversaries may abuse SQL stored procedures to establish persistent access to systems. SQL Stored Procedures are code that can be saved and reused so that database users do not waste time rewriting frequently used SQL queries. Stored procedures can be invoked via SQL statements to the database using the procedure name or via defined events (e.g. when a SQL server application is started/restarted)."
            },
            {
                "sub-technique": "Web Shell",
                "id": "T1505.003",
                "link": "https://attack.mitre.org/techniques/T1505/003",
                "description": "Adversaries may backdoor web servers with web shells to establish persistent access to systems. A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to use the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server."
            },
            {
                "sub-technique": "Terminal Services DLL",
                "id": "T1505.005",
                "link": "https://attack.mitre.org/techniques/T1505/005",
                "description": "Adversaries may abuse components of Terminal Services to enable persistent access to systems. Microsoft Terminal Services, renamed to Remote Desktop Services in some Windows Server OSs as of 2022, enable remote terminal connections to hosts. Terminal Services allows servers to transmit a full, interactive, graphical user interface to clients via RDP."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Code Signing",
                "id": "M1045",
                "link": "https://attack.mitre.org/mitigations/M1045",
                "description": "Enforce binary and application integrity with digital signature verification to prevent untrusted code from executing."
            },
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Restrict Registry Permissions",
                "id": "M1024",
                "link": "https://attack.mitre.org/mitigations/M1024",
                "description": "Restrict the ability to modify certain hives or keys in the Windows Registry."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Traffic Signaling",
        "id": "T1205",
        "link": "https://attack.mitre.org/techniques/T1205",
        "description": "Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control. Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port or executing a malicious task. This may take the form of sending a series of packets with certain characteristics before a port will be opened that the adversary can use for command and control. Usually this series of packets consists of attempted connections to a predefined sequence of closed ports (i.e. Port Knocking), but can involve unusual flags, specific strings, or other unique characteristics. After the sequence is completed, opening a port may be accomplished by the host-based firewall, but could also be implemented by custom software.",
        "sub-techniques": [
            {
                "sub-technique": "Port Knocking",
                "id": "T1205.001",
                "link": "https://attack.mitre.org/techniques/T1205/001",
                "description": "Adversaries may use port knocking to hide open ports used for persistence or command and control. To enable a port, an adversary sends a series of attempted connections to a predefined sequence of closed ports. After the sequence is completed, opening a port is often accomplished by the host based firewall, but could also be implemented by custom software."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            }
        ]
    },
    {
        "technique": "Valid Accounts",
        "id": "T1078",
        "link": "https://attack.mitre.org/techniques/T1078",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access, network devices, and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.",
        "sub-techniques": [
            {
                "sub-technique": "Default Accounts",
                "id": "T1078.001",
                "link": "https://attack.mitre.org/techniques/T1078/001",
                "description": "Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems. Default accounts also include default factory/provider set accounts on other types of systems, software, or devices, including the root user account in AWS and the default service account in Kubernetes."
            },
            {
                "sub-technique": "Local Accounts",
                "id": "T1078.003",
                "link": "https://attack.mitre.org/techniques/T1078/003",
                "description": "Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Account Use Policies",
                "id": "M1036",
                "link": "https://attack.mitre.org/mitigations/M1036",
                "description": "Configure features related to account use like login attempt lockouts, specific login times, etc."
            },
            {
                "mitigation": "Active Directory Configuration",
                "id": "M1015",
                "link": "https://attack.mitre.org/mitigations/M1015",
                "description": "Configure Active Directory to prevent use of certain techniques; use SID Filtering, etc."
            },
            {
                "mitigation": "Application Developer Guidance",
                "id": "M1013",
                "link": "https://attack.mitre.org/mitigations/M1013",
                "description": "This mitigation describes any guidance or training given to developers of applications to avoid introducing security weaknesses that an adversary may be able to take advantage of."
            },
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    }
]

privilege_escalation = [
    {
        "technique": "Abuse Elevation Control Mechanism",
        "id": "T1548",
        "link": "https://attack.mitre.org/techniques/T1548",
        "description": "Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.",
        "sub-techniques": [
            {
                "sub-technique": "Setuid and Setgid",
                "id": "T1548.001",
                "link": "https://attack.mitre.org/techniques/T1548/001",
                "description": "An adversary may abuse configurations where an application has the setuid or setgid bits set in order to get code running in a different (and possibly more privileged) user’s context. On Linux or macOS, when the setuid or setgid bits are set for an application binary, the application will run with the privileges of the owning user or group respectively. Normally an application is run in the current user’s context, regardless of which user or group owns the application. However, there are instances where programs need to be executed in an elevated context to function properly, but the user running them may not have the specific required privileges."
            },
            {
                "sub-technique": "Sudo and Sudo Caching",
                "id": "T1548.003",
                "link": "https://attack.mitre.org/techniques/T1548/003",
                "description": "Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges. Adversaries may do this to execute commands as other users or spawn processes with higher privileges."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            },
            {
                "mitigation": "User Account Control",
                "id": "M1052",
                "link": "https://attack.mitre.org/mitigations/M1052",
                "description": "Configure Windows User Account Control to mitigate risk of adversaries obtaining elevated process access."
            }
        ]
    },
    {
        "technique": "Access Token Manipulation",
        "id": "T1134",
        "link": "https://attack.mitre.org/techniques/T1134",
        "description": "Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token.",
        "sub-techniques": [
            {
                "sub-technique": "Token Impersonation/Theft",
                "id": "T1134.001",
                "link": "https://attack.mitre.org/techniques/T1134/001",
                "description": "Adversaries may duplicate then impersonate another user's existing token to escalate privileges and bypass access controls. For example, an adversary can duplicate an existing token using DuplicateToken or DuplicateTokenEx. The token can then be used with ImpersonateLoggedOnUser to allow the calling thread to impersonate a logged on user's security context, or with SetThreadToken to assign the impersonated token to a thread."
            },
            {
                "sub-technique": "Make and Impersonate Token",
                "id": "T1134.003",
                "link": "https://attack.mitre.org/techniques/T1134/003",
                "description": "Adversaries may make new tokens and impersonate users to escalate privileges and bypass access controls. For example, if an adversary has a username and password but the user is not logged onto the system the adversary can then create a logon session for the user using the LogonUser function. The function will return a copy of the new session's access token and the adversary can use SetThreadToken to assign the token to a thread."
            },
            {
                "sub-technique": "SID-History Injection",
                "id": "T1134.005",
                "link": "https://attack.mitre.org/techniques/T1134/005",
                "description": "Adversaries may use SID-History Injection to escalate privileges and bypass access controls. The Windows security identifier (SID) is a unique value that identifies a user or group account. SIDs are used by Windows security in both security descriptors and access tokens.  An account can hold additional SIDs in the SID-History Active Directory attribute , allowing inter-operable account migration between domains (e.g., all values in SID-History are included in access tokens)."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Boot or Logon Autostart Execution",
        "id": "T1547",
        "link": "https://attack.mitre.org/techniques/T1547",
        "description": "Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon. These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel.",
        "sub-techniques": [
            {
                "sub-technique": "Registry Run Keys / Startup Folder",
                "id": "T1547.001",
                "link": "https://attack.mitre.org/techniques/T1547/001",
                "description": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the \"run keys\" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. These programs will be executed under the context of the user and will have the account's associated permissions level."
            },
            {
                "sub-technique": "Time Providers",
                "id": "T1547.003",
                "link": "https://attack.mitre.org/techniques/T1547/003",
                "description": "Adversaries may abuse time providers to execute DLLs when the system boots. The Windows Time service (W32Time) enables time synchronization across and within domains. W32Time time providers are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients."
            },
            {
                "sub-technique": "Security Support Provider",
                "id": "T1547.005",
                "link": "https://attack.mitre.org/techniques/T1547/005",
                "description": "Adversaries may abuse security support providers (SSPs) to execute DLLs when the system boots. Windows SSP DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs."
            },
            {
                "sub-technique": "Re-opened Applications",
                "id": "T1547.007",
                "link": "https://attack.mitre.org/techniques/T1547/007",
                "description": "Adversaries may modify plist files to automatically run an application when a user logs in. When a user logs out or restarts via the macOS Graphical User Interface (GUI), a prompt is provided to the user with a checkbox to \"Reopen windows when logging back in\". When selected, all applications currently open are added to a property list file named com.apple.loginwindow.[UUID].plist within the ~/Library/Preferences/ByHost directory. Applications listed in this file are automatically reopened upon the user’s next logon."
            },
            {
                "sub-technique": "Shortcut Modification",
                "id": "T1547.009",
                "link": "https://attack.mitre.org/techniques/T1547/009",
                "description": "Adversaries may create or modify shortcuts that can execute a program during system boot or user login. Shortcuts or symbolic links are used to reference other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process."
            },
            {
                "sub-technique": "Print Processors",
                "id": "T1547.012",
                "link": "https://attack.mitre.org/techniques/T1547/012",
                "description": "Adversaries may abuse print processors to run malicious DLLs during system boot for persistence and/or privilege escalation. Print processors are DLLs that are loaded by the print spooler service, spoolsv.exe, during boot."
            },
            {
                "sub-technique": "Active Setup",
                "id": "T1547.014",
                "link": "https://attack.mitre.org/techniques/T1547/014",
                "description": "Adversaries may achieve persistence by adding a Registry key to the Active Setup of the local machine. Active Setup is a Windows mechanism that is used to execute programs when a user logs in. The value stored in the Registry key will be executed after a user logs into the computer. These programs will be executed under the context of the user and will have the account's associated permissions level."
            }
        ],
        "mitigations": []
    },
    {
        "technique": "Boot or Logon Initialization Scripts",
        "id": "T1037",
        "link": "https://attack.mitre.org/techniques/T1037",
        "description": "Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence. Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating system and whether applied locally or remotely.",
        "sub-techniques": [
            {
                "sub-technique": "Logon Script (Windows)",
                "id": "T1037.001",
                "link": "https://attack.mitre.org/techniques/T1037/001",
                "description": "Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence. Windows allows logon scripts to be run whenever a specific user or group of users log into a system. This is done via adding a path to a script to the HKCU\\Environment\\UserInitMprLogonScript Registry key."
            },
            {
                "sub-technique": "Network Logon Script",
                "id": "T1037.003",
                "link": "https://attack.mitre.org/techniques/T1037/003",
                "description": "Adversaries may use network logon scripts automatically executed at logon initialization to establish persistence. Network logon scripts can be assigned using Active Directory or Group Policy Objects. These logon scripts run with the privileges of the user they are assigned to. Depending on the systems within the network, initializing one of these scripts could apply to more than one or potentially all systems."
            },
            {
                "sub-technique": "Startup Items",
                "id": "T1037.005",
                "link": "https://attack.mitre.org/techniques/T1037/005",
                "description": "Adversaries may use startup items automatically executed at boot initialization to establish persistence. Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            },
            {
                "mitigation": "Restrict Registry Permissions",
                "id": "M1024",
                "link": "https://attack.mitre.org/mitigations/M1024",
                "description": "Restrict the ability to modify certain hives or keys in the Windows Registry."
            }
        ]
    },
    {
        "technique": "Create or Modify System Process",
        "id": "T1543",
        "link": "https://attack.mitre.org/techniques/T1543",
        "description": "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services. On macOS, launchd processes known as Launch Daemon and Launch Agent are run to finish system initialization and load user specific parameters.",
        "sub-techniques": [
            {
                "sub-technique": "Launch Agent",
                "id": "T1543.001",
                "link": "https://attack.mitre.org/techniques/T1543/001",
                "description": "Adversaries may create or modify launch agents to repeatedly execute malicious payloads as part of persistence. When a user logs in, a per-user launchd process is started which loads the parameters for each launch-on-demand user agent from the property list (.plist) file found in /System/Library/LaunchAgents, /Library/LaunchAgents, and ~/Library/LaunchAgents.  Property list files use the Label, ProgramArguments , and RunAtLoad keys to identify the Launch Agent's name, executable location, and execution time. Launch Agents are often installed to perform updates to programs, launch user specified programs at login, or to conduct other developer tasks."
            },
            {
                "sub-technique": "Windows Service",
                "id": "T1543.003",
                "link": "https://attack.mitre.org/techniques/T1543/003",
                "description": "Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions. Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Windows Registry."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Code Signing",
                "id": "M1045",
                "link": "https://attack.mitre.org/mitigations/M1045",
                "description": "Enforce binary and application integrity with digital signature verification to prevent untrusted code from executing."
            },
            {
                "mitigation": "Limit Software Installation",
                "id": "M1033",
                "link": "https://attack.mitre.org/mitigations/M1033",
                "description": "Block users or groups from installing unapproved software."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Domain Policy Modification",
        "id": "T1484",
        "link": "https://attack.mitre.org/techniques/T1484",
        "description": "Adversaries may modify the configuration settings of a domain to evade defenses and/or escalate privileges in domain environments. Domains provide a centralized means of managing how computer resources (ex: computers, user accounts) can act, and interact with each other, on a network. The policy of the domain also includes configuration settings that may apply between domains in a multi-domain/forest environment. Modifications to domain settings may include altering domain Group Policy Objects (GPOs) or changing trust settings for domains, including federation trusts.",
        "sub-techniques": [
            {
                "sub-technique": "Group Policy Modification",
                "id": "T1484.001",
                "link": "https://attack.mitre.org/techniques/T1484/001",
                "description": "Adversaries may modify Group Policy Objects (GPOs) to subvert the intended discretionary access controls for a domain, usually with the intention of escalating privileges on the domain. Group policy allows for centralized management of user and computer settings in Active Directory (AD). GPOs are containers for group policy settings made up of files stored within a predictable network path \\<DOMAIN>\\SYSVOL\\<DOMAIN>\\Policies\\."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Escape to Host",
        "id": "T1611",
        "link": "https://attack.mitre.org/techniques/T1611",
        "description": "Adversaries may break out of a container to gain access to the underlying host. This can allow an adversary access to other containerized resources from the host level or to the host itself. In principle, containerized resources should provide a clear separation of application functionality and be isolated from the host environment.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Application Isolation and Sandboxing",
                "id": "M1048",
                "link": "https://attack.mitre.org/mitigations/M1048",
                "description": "Restrict execution of code to a virtual environment on or in transit to an endpoint system."
            },
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            }
        ]
    },
    {
        "technique": "Event Triggered Execution",
        "id": "T1546",
        "link": "https://attack.mitre.org/techniques/T1546",
        "description": "Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries. Cloud environments may also support various functions and services that monitor and can be invoked in response to specific cloud events.",
        "sub-techniques": [
            {
                "sub-technique": "Change Default File Association",
                "id": "T1546.001",
                "link": "https://attack.mitre.org/techniques/T1546/001",
                "description": "Adversaries may establish persistence by executing malicious content triggered by a file type association. When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened."
            },
            {
                "sub-technique": "Windows Management Instrumentation Event Subscription",
                "id": "T1546.003",
                "link": "https://attack.mitre.org/techniques/T1546/003",
                "description": "Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription. WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Examples of events that may be subscribed to are the wall clock time, user loging, or the computer's uptime."
            },
            {
                "sub-technique": "Trap",
                "id": "T1546.005",
                "link": "https://attack.mitre.org/techniques/T1546/005",
                "description": "Adversaries may establish persistence by executing malicious content triggered by an interrupt signal. The trap command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like ctrl+c and ctrl+d."
            },
            {
                "sub-technique": "Netsh Helper DLL",
                "id": "T1546.007",
                "link": "https://attack.mitre.org/techniques/T1546/007",
                "description": "Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs. Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system. It contains functionality to add helper DLLs for extending functionality of the utility. The paths to registered netsh.exe helper DLLs are entered into the Windows Registry at HKLM\\SOFTWARE\\Microsoft\\Netsh."
            },
            {
                "sub-technique": "AppCert DLLs",
                "id": "T1546.009",
                "link": "https://attack.mitre.org/techniques/T1546/009",
                "description": "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppCert DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs Registry key under HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\ are loaded into every process that calls the ubiquitously used application programming interface (API) functions CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW, CreateProcessWithTokenW, or WinExec."
            },
            {
                "sub-technique": "Application Shimming",
                "id": "T1546.011",
                "link": "https://attack.mitre.org/techniques/T1546/011",
                "description": "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims. The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time. For example, the application shimming feature allows developers to apply fixes to applications (without rewriting code) that were created for Windows XP so that it will work with Windows 10."
            },
            {
                "sub-technique": "PowerShell Profile",
                "id": "T1546.013",
                "link": "https://attack.mitre.org/techniques/T1546/013",
                "description": "Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles. A PowerShell profile  (profile.ps1) is a script that runs when PowerShell starts and can be used as a logon script to customize user environments."
            },
            {
                "sub-technique": "Component Object Model Hijacking",
                "id": "T1546.015",
                "link": "https://attack.mitre.org/techniques/T1546/015",
                "description": "Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects. COM is a system within Windows to enable interaction between software components through the operating system.  References to various COM objects are stored in the Registry."
            }
        ],
        "mitigations": []
    },
    {
        "technique": "Exploitation for Privilege Escalation",
        "id": "T1068",
        "link": "https://attack.mitre.org/techniques/T1068",
        "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Security constructs such as permission levels will often hinder access to information and use of certain techniques, so adversaries will likely need to perform privilege escalation to include use of software exploitation to circumvent those restrictions.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Application Isolation and Sandboxing",
                "id": "M1048",
                "link": "https://attack.mitre.org/mitigations/M1048",
                "description": "Restrict execution of code to a virtual environment on or in transit to an endpoint system."
            },
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            },
            {
                "mitigation": "Exploit Protection",
                "id": "M1050",
                "link": "https://attack.mitre.org/mitigations/M1050",
                "description": "Use capabilities to detect and block conditions that may lead to or be indicative of a software exploit occurring."
            },
            {
                "mitigation": "Threat Intelligence Program",
                "id": "M1019",
                "link": "https://attack.mitre.org/mitigations/M1019",
                "description": "A threat intelligence program helps an organization generate their own threat intelligence information and track trends to inform defensive priorities to mitigate risk."
            },
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            }
        ]
    },
    {
        "technique": "Hijack Execution Flow",
        "id": "T1574",
        "link": "https://attack.mitre.org/techniques/T1574",
        "description": "Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.",
        "sub-techniques": [
            {
                "sub-technique": "DLL Search Order Hijacking",
                "id": "T1574.001",
                "link": "https://attack.mitre.org/techniques/T1574/001",
                "description": "Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs. Windows systems use a common method to look for required DLLs to load into a program.  Hijacking DLL loads may be for the purpose of establishing persistence as well as elevating privileges and/or evading restrictions on file execution."
            },
            {
                "sub-technique": "Dylib Hijacking",
                "id": "T1574.004",
                "link": "https://attack.mitre.org/techniques/T1574/004",
                "description": "Adversaries may execute their own payloads by placing a malicious dynamic library (dylib) with an expected name in a path a victim application searches at runtime. The dynamic loader will try to find the dylibs based on the sequential order of the search paths. Paths to dylibs may be prefixed with @rpath, which allows developers to use relative paths to specify an array of search paths used at runtime based on the location of the executable.  Additionally, if weak linking is used, such as the LC_LOAD_WEAK_DYLIB function, an application will still execute even if an expected dylib is not present. Weak linking enables developers to run an application on multiple macOS versions as new APIs are added."
            },
            {
                "sub-technique": "Dynamic Linker Hijacking",
                "id": "T1574.006",
                "link": "https://attack.mitre.org/techniques/T1574/006",
                "description": "Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries. During the execution preparation phase of a program, the dynamic linker loads specified absolute paths of shared libraries from environment variables and files, such as LD_PRELOAD on Linux or DYLD_INSERT_LIBRARIES on macOS. Libraries specified in environment variables are loaded first, taking precedence over system libraries with the same function name. These variables are often used by developers to debug binaries without needing to recompile, deconflict mapped symbols, and implement custom functions without changing the original library."
            },
            {
                "sub-technique": "Path Interception by Search Order Hijacking",
                "id": "T1574.008",
                "link": "https://attack.mitre.org/techniques/T1574/008",
                "description": "Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the calling program is located, causing the operating system to launch their malicious software at the request of the calling program."
            },
            {
                "sub-technique": "Services File Permissions Weakness",
                "id": "T1574.010",
                "link": "https://attack.mitre.org/techniques/T1574/010",
                "description": "Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM."
            },
            {
                "sub-technique": "COR_PROFILER",
                "id": "T1574.012",
                "link": "https://attack.mitre.org/techniques/T1574/012",
                "description": "Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the .NET CLR. The COR_PROFILER is a .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR). These profilers are designed to monitor, troubleshoot, and debug managed code executed by the .NET CLR."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Application Developer Guidance",
                "id": "M1013",
                "link": "https://attack.mitre.org/mitigations/M1013",
                "description": "This mitigation describes any guidance or training given to developers of applications to avoid introducing security weaknesses that an adversary may be able to take advantage of."
            },
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            },
            {
                "mitigation": "Restrict Library Loading",
                "id": "M1044",
                "link": "https://attack.mitre.org/mitigations/M1044",
                "description": "Prevent abuse of library loading mechanisms in the operating system and software to load untrusted code by configuring appropriate library loading mechanisms and investigating potential vulnerable software."
            },
            {
                "mitigation": "Restrict Registry Permissions",
                "id": "M1024",
                "link": "https://attack.mitre.org/mitigations/M1024",
                "description": "Restrict the ability to modify certain hives or keys in the Windows Registry."
            },
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            },
            {
                "mitigation": "User Account Control",
                "id": "M1052",
                "link": "https://attack.mitre.org/mitigations/M1052",
                "description": "Configure Windows User Account Control to mitigate risk of adversaries obtaining elevated process access."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Process Injection",
        "id": "T1055",
        "link": "https://attack.mitre.org/techniques/T1055",
        "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process.",
        "sub-techniques": [
            {
                "sub-technique": "Dynamic-link Library Injection",
                "id": "T1055.001",
                "link": "https://attack.mitre.org/techniques/T1055/001",
                "description": "Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges. DLL injection is a method of executing arbitrary code in the address space of a separate live process."
            },
            {
                "sub-technique": "Thread Execution Hijacking",
                "id": "T1055.003",
                "link": "https://attack.mitre.org/techniques/T1055/003",
                "description": "Adversaries may inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. Thread Execution Hijacking is a method of executing arbitrary code in the address space of a separate live process."
            },
            {
                "sub-technique": "Thread Local Storage",
                "id": "T1055.005",
                "link": "https://attack.mitre.org/techniques/T1055/005",
                "description": "Adversaries may inject malicious code into processes via thread local storage (TLS) callbacks in order to evade process-based defenses as well as possibly elevate privileges. TLS callback injection is a method of executing arbitrary code in the address space of a separate live process."
            },
            {
                "sub-technique": "Proc Memory",
                "id": "T1055.009",
                "link": "https://attack.mitre.org/techniques/T1055/009",
                "description": "Adversaries may inject malicious code into processes via the /proc filesystem in order to evade process-based defenses as well as possibly elevate privileges. Proc memory injection is a method of executing arbitrary code in the address space of a separate live process."
            },
            {
                "sub-technique": "Process Hollowing",
                "id": "T1055.012",
                "link": "https://attack.mitre.org/techniques/T1055/012",
                "description": "Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. Process hollowing is a method of executing arbitrary code in the address space of a separate live process."
            },
            {
                "sub-technique": "VDSO Hijacking",
                "id": "T1055.014",
                "link": "https://attack.mitre.org/techniques/T1055/014",
                "description": "Adversaries may inject malicious code into processes via VDSO hijacking in order to evade process-based defenses as well as possibly elevate privileges. Virtual dynamic shared object (vdso) hijacking is a method of executing arbitrary code in the address space of a separate live process."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            }
        ]
    },
    {
        "technique": "Scheduled Task/Job",
        "id": "T1053",
        "link": "https://attack.mitre.org/techniques/T1053",
        "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically may require being a member of an admin or otherwise privileged group on the remote system.",
        "sub-techniques": [
            {
                "sub-technique": "At",
                "id": "T1053.002",
                "link": "https://attack.mitre.org/techniques/T1053/002",
                "description": "Adversaries may abuse the at utility to perform task scheduling for initial or recurring execution of malicious code. The at utility exists as an executable within Windows, Linux, and macOS for scheduling tasks at a specified time and date. Although deprecated in favor of Scheduled Task's schtasks in Windows environments, using at requires that the Task Scheduler service be running, and the user to be logged on as a member of the local Administrators group."
            },
            {
                "sub-technique": "Scheduled Task",
                "id": "T1053.005",
                "link": "https://attack.mitre.org/techniques/T1053/005",
                "description": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The schtasks utility can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel. In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library to create a scheduled task."
            },
            {
                "sub-technique": "Container Orchestration Job",
                "id": "T1053.007",
                "link": "https://attack.mitre.org/techniques/T1053/007",
                "description": "Adversaries may abuse task scheduling functionality provided by container orchestration tools such as Kubernetes to schedule deployment of containers configured to execute malicious code. Container orchestration jobs run these automated tasks at a specific date and time, similar to cron jobs on a Linux system. Deployments of this type can also be configured to maintain a quantity of containers over time, automating the process of maintaining persistence within a cluster."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Valid Accounts",
        "id": "T1078",
        "link": "https://attack.mitre.org/techniques/T1078",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access, network devices, and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.",
        "sub-techniques": [
            {
                "sub-technique": "Default Accounts",
                "id": "T1078.001",
                "link": "https://attack.mitre.org/techniques/T1078/001",
                "description": "Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems. Default accounts also include default factory/provider set accounts on other types of systems, software, or devices, including the root user account in AWS and the default service account in Kubernetes."
            },
            {
                "sub-technique": "Local Accounts",
                "id": "T1078.003",
                "link": "https://attack.mitre.org/techniques/T1078/003",
                "description": "Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Account Use Policies",
                "id": "M1036",
                "link": "https://attack.mitre.org/mitigations/M1036",
                "description": "Configure features related to account use like login attempt lockouts, specific login times, etc."
            },
            {
                "mitigation": "Active Directory Configuration",
                "id": "M1015",
                "link": "https://attack.mitre.org/mitigations/M1015",
                "description": "Configure Active Directory to prevent use of certain techniques; use SID Filtering, etc."
            },
            {
                "mitigation": "Application Developer Guidance",
                "id": "M1013",
                "link": "https://attack.mitre.org/mitigations/M1013",
                "description": "This mitigation describes any guidance or training given to developers of applications to avoid introducing security weaknesses that an adversary may be able to take advantage of."
            },
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    }
]

defense_evasion = [
    {
        "technique": "Abuse Elevation Control Mechanism",
        "id": "T1548",
        "link": "https://attack.mitre.org/techniques/T1548",
        "description": "Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.",
        "sub-techniques": [
            {
                "sub-technique": "Setuid and Setgid",
                "id": "T1548.001",
                "link": "https://attack.mitre.org/techniques/T1548/001",
                "description": "An adversary may abuse configurations where an application has the setuid or setgid bits set in order to get code running in a different (and possibly more privileged) user’s context. On Linux or macOS, when the setuid or setgid bits are set for an application binary, the application will run with the privileges of the owning user or group respectively. Normally an application is run in the current user’s context, regardless of which user or group owns the application. However, there are instances where programs need to be executed in an elevated context to function properly, but the user running them may not have the specific required privileges."
            },
            {
                "sub-technique": "Sudo and Sudo Caching",
                "id": "T1548.003",
                "link": "https://attack.mitre.org/techniques/T1548/003",
                "description": "Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges. Adversaries may do this to execute commands as other users or spawn processes with higher privileges."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            },
            {
                "mitigation": "User Account Control",
                "id": "M1052",
                "link": "https://attack.mitre.org/mitigations/M1052",
                "description": "Configure Windows User Account Control to mitigate risk of adversaries obtaining elevated process access."
            }
        ]
    },
    {
        "technique": "Access Token Manipulation",
        "id": "T1134",
        "link": "https://attack.mitre.org/techniques/T1134",
        "description": "Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token.",
        "sub-techniques": [
            {
                "sub-technique": "Token Impersonation/Theft",
                "id": "T1134.001",
                "link": "https://attack.mitre.org/techniques/T1134/001",
                "description": "Adversaries may duplicate then impersonate another user's existing token to escalate privileges and bypass access controls. For example, an adversary can duplicate an existing token using DuplicateToken or DuplicateTokenEx. The token can then be used with ImpersonateLoggedOnUser to allow the calling thread to impersonate a logged on user's security context, or with SetThreadToken to assign the impersonated token to a thread."
            },
            {
                "sub-technique": "Make and Impersonate Token",
                "id": "T1134.003",
                "link": "https://attack.mitre.org/techniques/T1134/003",
                "description": "Adversaries may make new tokens and impersonate users to escalate privileges and bypass access controls. For example, if an adversary has a username and password but the user is not logged onto the system the adversary can then create a logon session for the user using the LogonUser function. The function will return a copy of the new session's access token and the adversary can use SetThreadToken to assign the token to a thread."
            },
            {
                "sub-technique": "SID-History Injection",
                "id": "T1134.005",
                "link": "https://attack.mitre.org/techniques/T1134/005",
                "description": "Adversaries may use SID-History Injection to escalate privileges and bypass access controls. The Windows security identifier (SID) is a unique value that identifies a user or group account. SIDs are used by Windows security in both security descriptors and access tokens.  An account can hold additional SIDs in the SID-History Active Directory attribute , allowing inter-operable account migration between domains (e.g., all values in SID-History are included in access tokens)."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "BITS Jobs",
        "id": "T1197",
        "link": "https://attack.mitre.org/techniques/T1197",
        "description": "Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM). BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Build Image on Host",
        "id": "T1612",
        "link": "https://attack.mitre.org/techniques/T1612",
        "description": "Adversaries may build a container image directly on a host to bypass defenses that monitor for the retrieval of malicious images from a public registry. A remote build request may be sent to the Docker API that includes a Dockerfile that pulls a vanilla base image, such as alpine, from a public or local registry and then builds a custom image upon it.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Limit Access to Resource Over Network",
                "id": "M1035",
                "link": "https://attack.mitre.org/mitigations/M1035",
                "description": "Prevent access to file shares, remote access to systems, unnecessary services. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            }
        ]
    },
    {
        "technique": "Debugger Evasion",
        "id": "T1622",
        "link": "https://attack.mitre.org/techniques/T1622",
        "description": "Adversaries may employ various means to detect and avoid debuggers. Debuggers are typically used by defenders to trace and/or analyze the execution of potential malware payloads.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Deobfuscate/Decode Files or Information",
        "id": "T1140",
        "link": "https://attack.mitre.org/techniques/T1140",
        "description": "Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it. Methods for doing that include built-in functionality of malware or by using utilities present on the system.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Deploy Container",
        "id": "T1610",
        "link": "https://attack.mitre.org/techniques/T1610",
        "description": "Adversaries may deploy a container into an environment to facilitate execution or evade defenses. In some cases, adversaries may deploy a new container to execute processes associated with a particular image or deployment, such as processes that execute or download malware. In others, an adversary may deploy a new container configured without network rules, user limitations, etc. to bypass existing defenses within the environment.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Limit Access to Resource Over Network",
                "id": "M1035",
                "link": "https://attack.mitre.org/mitigations/M1035",
                "description": "Prevent access to file shares, remote access to systems, unnecessary services. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Direct Volume Access",
        "id": "T1006",
        "link": "https://attack.mitre.org/techniques/T1006",
        "description": "Adversaries may directly access a volume to bypass file access controls and file system monitoring. Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by analyzing file system data structures. This technique bypasses Windows file access controls as well as file system monitoring tools.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Domain Policy Modification",
        "id": "T1484",
        "link": "https://attack.mitre.org/techniques/T1484",
        "description": "Adversaries may modify the configuration settings of a domain to evade defenses and/or escalate privileges in domain environments. Domains provide a centralized means of managing how computer resources (ex: computers, user accounts) can act, and interact with each other, on a network. The policy of the domain also includes configuration settings that may apply between domains in a multi-domain/forest environment. Modifications to domain settings may include altering domain Group Policy Objects (GPOs) or changing trust settings for domains, including federation trusts.",
        "sub-techniques": [
            {
                "sub-technique": "Group Policy Modification",
                "id": "T1484.001",
                "link": "https://attack.mitre.org/techniques/T1484/001",
                "description": "Adversaries may modify Group Policy Objects (GPOs) to subvert the intended discretionary access controls for a domain, usually with the intention of escalating privileges on the domain. Group policy allows for centralized management of user and computer settings in Active Directory (AD). GPOs are containers for group policy settings made up of files stored within a predictable network path \\<DOMAIN>\\SYSVOL\\<DOMAIN>\\Policies\\."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Execution Guardrails",
        "id": "T1480",
        "link": "https://attack.mitre.org/techniques/T1480",
        "description": "Adversaries may use execution guardrails to constrain execution or actions based on adversary supplied and environment specific conditions that are expected to be present on the target. Guardrails ensure that a payload only executes against an intended target and reduces collateral damage from an adversary’s campaign. Values an adversary can provide about a target system or environment to use as guardrails may include specific network share names, attached physical devices, files, joined Active Directory (AD) domains, and local/external IP addresses.",
        "sub-techniques": [
            {
                "sub-technique": "Environmental Keying",
                "id": "T1480.001",
                "link": "https://attack.mitre.org/techniques/T1480/001",
                "description": "Adversaries may environmentally key payloads or other features of malware to evade defenses and constraint execution to a specific target environment. Environmental keying uses cryptography to constrain execution or actions based on adversary supplied environment specific conditions that are expected to be present on the target. Environmental keying is an implementation of Execution Guardrails that utilizes cryptographic techniques for deriving encryption/decryption keys from specific types of values in a given computing environment."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Do Not Mitigate",
                "id": "M1055",
                "link": "https://attack.mitre.org/mitigations/M1055",
                "description": "This category is to associate techniques that mitigation might increase risk of compromise and therefore mitigation is not recommended."
            }
        ]
    },
    {
        "technique": "Exploitation for Defense Evasion",
        "id": "T1211",
        "link": "https://attack.mitre.org/techniques/T1211",
        "description": "Adversaries may exploit a system or application vulnerability to bypass security features. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Vulnerabilities may exist in defensive security software that can be used to disable or circumvent them.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Application Isolation and Sandboxing",
                "id": "M1048",
                "link": "https://attack.mitre.org/mitigations/M1048",
                "description": "Restrict execution of code to a virtual environment on or in transit to an endpoint system."
            },
            {
                "mitigation": "Exploit Protection",
                "id": "M1050",
                "link": "https://attack.mitre.org/mitigations/M1050",
                "description": "Use capabilities to detect and block conditions that may lead to or be indicative of a software exploit occurring."
            },
            {
                "mitigation": "Threat Intelligence Program",
                "id": "M1019",
                "link": "https://attack.mitre.org/mitigations/M1019",
                "description": "A threat intelligence program helps an organization generate their own threat intelligence information and track trends to inform defensive priorities to mitigate risk."
            },
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            }
        ]
    },
    {
        "technique": "File and Directory Permissions Modification",
        "id": "T1222",
        "link": "https://attack.mitre.org/techniques/T1222",
        "description": "Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).",
        "sub-techniques": [
            {
                "sub-technique": "Windows File and Directory Permissions Modification",
                "id": "T1222.001",
                "link": "https://attack.mitre.org/techniques/T1222/001",
                "description": "Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.)."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            }
        ]
    },
    {
        "technique": "Hide Artifacts",
        "id": "T1564",
        "link": "https://attack.mitre.org/techniques/T1564",
        "description": "Adversaries may attempt to hide artifacts associated with their behaviors to evade detection. Operating systems may have features to hide various artifacts, such as important system files and administrative task execution, to avoid disrupting user work environments and prevent users from changing files or features on the system. Adversaries may abuse these features to hide artifacts such as files, directories, user accounts, or other system activity to evade detection.",
        "sub-techniques": [
            {
                "sub-technique": "Hidden Files and Directories",
                "id": "T1564.001",
                "link": "https://attack.mitre.org/techniques/T1564/001",
                "description": "Adversaries may set files and directories to be hidden to evade detection mechanisms. To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a ‘hidden’ file. These files don’t show up when a user browses the file system with a GUI or when using normal commands on the command line. Users must explicitly ask to show the hidden files either via a series of Graphical User Interface (GUI) prompts or with command line switches (dir /a for Windows and ls –a for Linux and macOS)."
            },
            {
                "sub-technique": "Hidden Window",
                "id": "T1564.003",
                "link": "https://attack.mitre.org/techniques/T1564/003",
                "description": "Adversaries may use hidden windows to conceal malicious activity from the plain sight of users. In some cases, windows that would typically be displayed when an application carries out an operation can be hidden. This may be utilized by system administrators to avoid disrupting user work environments when carrying out administrative tasks."
            },
            {
                "sub-technique": "Hidden File System",
                "id": "T1564.005",
                "link": "https://attack.mitre.org/techniques/T1564/005",
                "description": "Adversaries may use a hidden file system to conceal malicious activity from users and security tools. File systems provide a structure to store and access data from physical storage. Typically, a user engages with a file system through applications that allow them to access files and directories, which are an abstraction from their physical location (ex: disk sector). Standard file systems include FAT, NTFS, ext4, and APFS. File systems can also contain other structures, such as the Volume Boot Record (VBR) and Master File Table (MFT) in NTFS."
            },
            {
                "sub-technique": "VBA Stomping",
                "id": "T1564.007",
                "link": "https://attack.mitre.org/techniques/T1564/007",
                "description": "Adversaries may hide malicious Visual Basic for Applications (VBA) payloads embedded within MS Office documents by replacing the VBA source code with benign data."
            },
            {
                "sub-technique": "Resource Forking",
                "id": "T1564.009",
                "link": "https://attack.mitre.org/techniques/T1564/009",
                "description": "Adversaries may abuse resource forks to hide malicious code or executables to evade detection and bypass security applications. A resource fork provides applications a structured way to store resources such as thumbnail images, menu definitions, icons, dialog boxes, and code. Usage of a resource fork is identifiable when displaying a file’s extended attributes, using ls -l@ or xattr -l commands. Resource forks have been deprecated and replaced with the application bundle structure. Non-localized resources are placed at the top level directory of an application bundle, while localized resources are placed in the /Resources folder."
            }
        ],
        "mitigations": []
    },
    {
        "technique": "Hijack Execution Flow",
        "id": "T1574",
        "link": "https://attack.mitre.org/techniques/T1574",
        "description": "Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.",
        "sub-techniques": [
            {
                "sub-technique": "DLL Search Order Hijacking",
                "id": "T1574.001",
                "link": "https://attack.mitre.org/techniques/T1574/001",
                "description": "Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs. Windows systems use a common method to look for required DLLs to load into a program.  Hijacking DLL loads may be for the purpose of establishing persistence as well as elevating privileges and/or evading restrictions on file execution."
            },
            {
                "sub-technique": "Dylib Hijacking",
                "id": "T1574.004",
                "link": "https://attack.mitre.org/techniques/T1574/004",
                "description": "Adversaries may execute their own payloads by placing a malicious dynamic library (dylib) with an expected name in a path a victim application searches at runtime. The dynamic loader will try to find the dylibs based on the sequential order of the search paths. Paths to dylibs may be prefixed with @rpath, which allows developers to use relative paths to specify an array of search paths used at runtime based on the location of the executable.  Additionally, if weak linking is used, such as the LC_LOAD_WEAK_DYLIB function, an application will still execute even if an expected dylib is not present. Weak linking enables developers to run an application on multiple macOS versions as new APIs are added."
            },
            {
                "sub-technique": "Dynamic Linker Hijacking",
                "id": "T1574.006",
                "link": "https://attack.mitre.org/techniques/T1574/006",
                "description": "Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries. During the execution preparation phase of a program, the dynamic linker loads specified absolute paths of shared libraries from environment variables and files, such as LD_PRELOAD on Linux or DYLD_INSERT_LIBRARIES on macOS. Libraries specified in environment variables are loaded first, taking precedence over system libraries with the same function name. These variables are often used by developers to debug binaries without needing to recompile, deconflict mapped symbols, and implement custom functions without changing the original library."
            },
            {
                "sub-technique": "Path Interception by Search Order Hijacking",
                "id": "T1574.008",
                "link": "https://attack.mitre.org/techniques/T1574/008",
                "description": "Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the calling program is located, causing the operating system to launch their malicious software at the request of the calling program."
            },
            {
                "sub-technique": "Services File Permissions Weakness",
                "id": "T1574.010",
                "link": "https://attack.mitre.org/techniques/T1574/010",
                "description": "Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM."
            },
            {
                "sub-technique": "COR_PROFILER",
                "id": "T1574.012",
                "link": "https://attack.mitre.org/techniques/T1574/012",
                "description": "Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the .NET CLR. The COR_PROFILER is a .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR). These profilers are designed to monitor, troubleshoot, and debug managed code executed by the .NET CLR."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Application Developer Guidance",
                "id": "M1013",
                "link": "https://attack.mitre.org/mitigations/M1013",
                "description": "This mitigation describes any guidance or training given to developers of applications to avoid introducing security weaknesses that an adversary may be able to take advantage of."
            },
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            },
            {
                "mitigation": "Restrict Library Loading",
                "id": "M1044",
                "link": "https://attack.mitre.org/mitigations/M1044",
                "description": "Prevent abuse of library loading mechanisms in the operating system and software to load untrusted code by configuring appropriate library loading mechanisms and investigating potential vulnerable software."
            },
            {
                "mitigation": "Restrict Registry Permissions",
                "id": "M1024",
                "link": "https://attack.mitre.org/mitigations/M1024",
                "description": "Restrict the ability to modify certain hives or keys in the Windows Registry."
            },
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            },
            {
                "mitigation": "User Account Control",
                "id": "M1052",
                "link": "https://attack.mitre.org/mitigations/M1052",
                "description": "Configure Windows User Account Control to mitigate risk of adversaries obtaining elevated process access."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Impair Defenses",
        "id": "T1562",
        "link": "https://attack.mitre.org/techniques/T1562",
        "description": "Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as firewalls and anti-virus, but also detection capabilities that defenders can use to audit activity and identify malicious behavior. This may also span both native defenses as well as supplemental capabilities installed by users and administrators.",
        "sub-techniques": [
            {
                "sub-technique": "Disable or Modify Tools",
                "id": "T1562.001",
                "link": "https://attack.mitre.org/techniques/T1562/001",
                "description": "Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities. This may take many forms, such as killing security software processes or services, modifying / deleting Registry keys or configuration files so that tools do not operate properly, or other methods to interfere with security tools scanning or reporting information. Adversaries may also disable updates to prevent the latest security patches from reaching tools on victim systems."
            },
            {
                "sub-technique": "Impair Command History Logging",
                "id": "T1562.003",
                "link": "https://attack.mitre.org/techniques/T1562/003",
                "description": "Adversaries may impair command history logging to hide commands they run on a compromised system. Various command interpreters keep track of the commands users type in their terminal so that users can retrace what they've done."
            },
            {
                "sub-technique": "Indicator Blocking",
                "id": "T1562.006",
                "link": "https://attack.mitre.org/techniques/T1562/006",
                "description": "An adversary may attempt to block indicators or events typically captured by sensors from being gathered and analyzed. This could include maliciously redirecting or even disabling host-based sensors, such as Event Tracing for Windows (ETW), by tampering settings that control the collection and flow of event telemetry. These settings may be stored on the system in configuration files and/or in the Registry as well as being accessible via administrative utilities such as PowerShell or Windows Management Instrumentation."
            },
            {
                "sub-technique": "Disable Cloud Logs",
                "id": "T1562.008",
                "link": "https://attack.mitre.org/techniques/T1562/008",
                "description": "An adversary may disable cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection. Cloud environments allow for collection and analysis of audit and application logs that provide insight into what activities a user does within the environment. If an adversary has sufficient permissions, they can disable logging to avoid detection of their activities."
            },
            {
                "sub-technique": "Downgrade Attack",
                "id": "T1562.010",
                "link": "https://attack.mitre.org/techniques/T1562/010",
                "description": "Adversaries may downgrade or use a version of system features that may be outdated, vulnerable, and/or does not support updated security controls such as logging. For example, PowerShell versions 5+ includes Script Block Logging (SBL) which can record executed script content. However, adversaries may attempt to execute a previous version of PowerShell that does not support SBL with the intent to Impair Defenses while running malicious scripts that may have otherwise been detected."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            },
            {
                "mitigation": "Restrict Registry Permissions",
                "id": "M1024",
                "link": "https://attack.mitre.org/mitigations/M1024",
                "description": "Restrict the ability to modify certain hives or keys in the Windows Registry."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Indicator Removal",
        "id": "T1070",
        "link": "https://attack.mitre.org/techniques/T1070",
        "description": "Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses. Various artifacts may be created by an adversary or something that can be attributed to an adversary’s actions. Typically these artifacts are used as defensive indicators related to monitored events, such as strings from downloaded files, logs that are generated from user actions, and other data analyzed by defenders. Location, format, and type of artifact (such as command or login history) are often specific to each platform.",
        "sub-techniques": [
            {
                "sub-technique": "Clear Windows Event Logs",
                "id": "T1070.001",
                "link": "https://attack.mitre.org/techniques/T1070/001",
                "description": "Adversaries may clear Windows Event Logs to hide the activity of an intrusion. Windows Event Logs are a record of a computer's alerts and notifications. There are three system-defined sources of events: System, Application, and Security, with five event types: Error, Warning, Information, Success Audit, and Failure Audit."
            },
            {
                "sub-technique": "Clear Command History",
                "id": "T1070.003",
                "link": "https://attack.mitre.org/techniques/T1070/003",
                "description": "In addition to clearing system logs, an adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion. Various command interpreters keep track of the commands users type in their terminal so that users can retrace what they've done."
            },
            {
                "sub-technique": "Network Share Connection Removal",
                "id": "T1070.005",
                "link": "https://attack.mitre.org/techniques/T1070/005",
                "description": "Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation. Windows shared drive and SMB/Windows Admin Shares connections can be removed when no longer needed. Net is an example utility that can be used to remove network share connections with the net use \\system\\share /delete command."
            },
            {
                "sub-technique": "Clear Network Connection History and Configurations",
                "id": "T1070.007",
                "link": "https://attack.mitre.org/techniques/T1070/007",
                "description": "Adversaries may clear or remove evidence of malicious network connections in order to clean up traces of their operations. Configuration settings as well as various artifacts that highlight connection history may be created on a system from behaviors that require network connections, such as Remote Services or External Remote Services. Defenders may use these artifacts to monitor or otherwise analyze network connections created by adversaries."
            },
            {
                "sub-technique": "Clear Persistence",
                "id": "T1070.009",
                "link": "https://attack.mitre.org/techniques/T1070/009",
                "description": "Adversaries may clear artifacts associated with previously established persistence on a host system to remove evidence of their activity. This may involve various actions, such as removing services, deleting executables, Modify Registry, Plist File Modification, or other methods of cleanup to prevent defenders from collecting evidence of their persistent presence. Adversaries may also delete accounts previously created to maintain persistence (i.e. Create Account)."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Encrypt Sensitive Information",
                "id": "M1041",
                "link": "https://attack.mitre.org/mitigations/M1041",
                "description": "Protect sensitive information with strong encryption."
            },
            {
                "mitigation": "Remote Data Storage",
                "id": "M1029",
                "link": "https://attack.mitre.org/mitigations/M1029",
                "description": "Use remote security log and sensitive file storage where access can be controlled better to prevent exposure of intrusion detection log data or sensitive information."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            }
        ]
    },
    {
        "technique": "Indirect Command Execution",
        "id": "T1202",
        "link": "https://attack.mitre.org/techniques/T1202",
        "description": "Adversaries may abuse utilities that allow for command execution to bypass security restrictions that limit the use of command-line interpreters. Various Windows utilities may be used to execute commands, possibly without invoking cmd. For example, Forfiles, the Program Compatibility Assistant (pcalua.exe), components of the Windows Subsystem for Linux (WSL), as well as other utilities may invoke the execution of programs and commands from a Command and Scripting Interpreter, Run window, or via scripts.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Masquerading",
        "id": "T1036",
        "link": "https://attack.mitre.org/techniques/T1036",
        "description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. This may include manipulating file metadata, tricking users into misidentifying the file type, and giving legitimate task or service names.",
        "sub-techniques": [
            {
                "sub-technique": "Invalid Code Signature",
                "id": "T1036.001",
                "link": "https://attack.mitre.org/techniques/T1036/001",
                "description": "Adversaries may attempt to mimic features of valid code signatures to increase the chance of deceiving a user, analyst, or tool. Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with. Adversaries can copy the metadata and signature information from a signed program, then use it as a template for an unsigned program. Files with invalid code signatures will fail digital signature validation checks, but they may appear more legitimate to users and security tools may improperly handle these files."
            },
            {
                "sub-technique": "Rename System Utilities",
                "id": "T1036.003",
                "link": "https://attack.mitre.org/techniques/T1036/003",
                "description": "Adversaries may rename legitimate system utilities to try to evade security mechanisms concerning the usage of those utilities. Security monitoring and control mechanisms may be in place for system utilities adversaries are capable of abusing.  It may be possible to bypass those security mechanisms by renaming the utility prior to utilization (ex: rename rundll32.exe).  An alternative case occurs when a legitimate utility is copied or moved to a different directory and renamed to avoid detections based on system utilities executing from non-standard paths."
            },
            {
                "sub-technique": "Match Legitimate Name or Location",
                "id": "T1036.005",
                "link": "https://attack.mitre.org/techniques/T1036/005",
                "description": "Adversaries may match or approximate the name or location of legitimate files or resources when naming/placing them. This is done for the sake of evading defenses and observation. This may be done by placing an executable in a commonly trusted directory (ex: under System32) or giving it the name of a legitimate, trusted program (ex: svchost.exe). In containerized environments, this may also be done by creating a resource in a namespace that matches the naming convention of a container pod or cluster. Alternatively, a file or container image name given may be a close approximation to legitimate programs/images or something innocuous."
            },
            {
                "sub-technique": "Double File Extension",
                "id": "T1036.007",
                "link": "https://attack.mitre.org/techniques/T1036/007",
                "description": "Adversaries may abuse a double extension in the filename as a means of masquerading the true file type. A file name may include a secondary file type extension that may cause only the first extension to be displayed (ex: File.txt.exe may render in some views as just File.txt). However, the second extension is the true file type that determines how the file is opened and executed. The real file extension may be hidden by the operating system in the file browser (ex: explorer.exe), as well as in any software configured using or similar to the system’s policies."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Antivirus/Antimalware",
                "id": "M1049",
                "link": "https://attack.mitre.org/mitigations/M1049",
                "description": "Use signatures or heuristics to detect malicious software."
            },
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Code Signing",
                "id": "M1045",
                "link": "https://attack.mitre.org/mitigations/M1045",
                "description": "Enforce binary and application integrity with digital signature verification to prevent untrusted code from executing."
            },
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            }
        ]
    },
    {
        "technique": "Modify Authentication Process",
        "id": "T1556",
        "link": "https://attack.mitre.org/techniques/T1556",
        "description": "Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials. By modifying an authentication process, an adversary may be able to authenticate to a service or system without using Valid Accounts.",
        "sub-techniques": [
            {
                "sub-technique": "Domain Controller Authentication",
                "id": "T1556.001",
                "link": "https://attack.mitre.org/techniques/T1556/001",
                "description": "Adversaries may patch the authentication process on a domain controller to bypass the typical authentication mechanisms and enable access to accounts."
            },
            {
                "sub-technique": "Pluggable Authentication Modules",
                "id": "T1556.003",
                "link": "https://attack.mitre.org/techniques/T1556/003",
                "description": "Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts. PAM is a modular system of configuration files, libraries, and executable files which guide authentication for many services. The most common authentication module is pam_unix.so, which retrieves, sets, and verifies account authentication information in /etc/passwd and /etc/shadow."
            },
            {
                "sub-technique": "Reversible Encryption",
                "id": "T1556.005",
                "link": "https://attack.mitre.org/techniques/T1556/005",
                "description": "An adversary may abuse Active Directory authentication encryption properties to gain access to credentials on Windows systems. The AllowReversiblePasswordEncryption property specifies whether reversible password encryption for an account is enabled or disabled. By default this property is disabled (instead storing user credentials as the output of one-way hashing functions) and should not be enabled unless legacy or other software require it."
            },
            {
                "sub-technique": "Hybrid Identity",
                "id": "T1556.007",
                "link": "https://attack.mitre.org/techniques/T1556/007",
                "description": "Adversaries may patch, modify, or otherwise backdoor cloud authentication processes that are tied to on-premises user identities in order to bypass typical authentication mechanisms, access credentials, and enable persistent access to accounts."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            },
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Privileged Process Integrity",
                "id": "M1025",
                "link": "https://attack.mitre.org/mitigations/M1025",
                "description": "Protect processes with high privileges that can be used to interact with critical system components through use of protected process light, anti-process injection defenses, or other process integrity enforcement measures."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            },
            {
                "mitigation": "Restrict Registry Permissions",
                "id": "M1024",
                "link": "https://attack.mitre.org/mitigations/M1024",
                "description": "Restrict the ability to modify certain hives or keys in the Windows Registry."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Modify Cloud Compute Infrastructure",
        "id": "T1578",
        "link": "https://attack.mitre.org/techniques/T1578",
        "description": "An adversary may attempt to modify a cloud account's compute service infrastructure to evade defenses. A modification to the compute service infrastructure can include the creation, deletion, or modification of one or more components such as compute instances, virtual machines, and snapshots.",
        "sub-techniques": [
            {
                "sub-technique": "Create Snapshot",
                "id": "T1578.001",
                "link": "https://attack.mitre.org/techniques/T1578/001",
                "description": "An adversary may create a snapshot or data backup within a cloud account to evade defenses. A snapshot is a point-in-time copy of an existing cloud compute component such as a virtual machine (VM), virtual hard drive, or volume. An adversary may leverage permissions to create a snapshot in order to bypass restrictions that prevent access to existing compute service infrastructure, unlike in Revert Cloud Instance where an adversary may revert to a snapshot to evade detection and remove evidence of their presence."
            },
            {
                "sub-technique": "Delete Cloud Instance",
                "id": "T1578.003",
                "link": "https://attack.mitre.org/techniques/T1578/003",
                "description": "An adversary may delete a cloud instance after they have performed malicious activities in an attempt to evade detection and remove evidence of their presence.  Deleting an instance or virtual machine can remove valuable forensic artifacts and other evidence of suspicious behavior if the instance is not recoverable."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Modify Registry",
        "id": "T1112",
        "link": "https://attack.mitre.org/techniques/T1112",
        "description": "Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Restrict Registry Permissions",
                "id": "M1024",
                "link": "https://attack.mitre.org/mitigations/M1024",
                "description": "Restrict the ability to modify certain hives or keys in the Windows Registry."
            }
        ]
    },
    {
        "technique": "Modify System Image",
        "id": "T1601",
        "link": "https://attack.mitre.org/techniques/T1601",
        "description": "Adversaries may make changes to the operating system of embedded network devices to weaken defenses and provide new capabilities for themselves.  On such devices, the operating systems are typically monolithic and most of the device functionality and capabilities are contained within a single file.",
        "sub-techniques": [
            {
                "sub-technique": "Patch System Image",
                "id": "T1601.001",
                "link": "https://attack.mitre.org/techniques/T1601/001",
                "description": "Adversaries may modify the operating system of a network device to introduce new capabilities or weaken existing defenses.     Some network devices are built with a monolithic architecture, where the entire operating system and most of the functionality of the device is contained within a single file.  Adversaries may change this file in storage, to be loaded in a future boot, or in memory during runtime."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Boot Integrity",
                "id": "M1046",
                "link": "https://attack.mitre.org/mitigations/M1046",
                "description": "Use secure methods to boot a system and verify the integrity of the operating system and loading mechanisms."
            },
            {
                "mitigation": "Code Signing",
                "id": "M1045",
                "link": "https://attack.mitre.org/mitigations/M1045",
                "description": "Enforce binary and application integrity with digital signature verification to prevent untrusted code from executing."
            },
            {
                "mitigation": "Credential Access Protection",
                "id": "M1043",
                "link": "https://attack.mitre.org/mitigations/M1043",
                "description": "Use capabilities to prevent successful credential access by adversaries; including blocking forms of credential dumping."
            },
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            }
        ]
    },
    {
        "technique": "Network Boundary Bridging",
        "id": "T1599",
        "link": "https://attack.mitre.org/techniques/T1599",
        "description": "Adversaries may bridge network boundaries by compromising perimeter network devices or internal devices responsible for network segmentation. Breaching these devices may enable an adversary to bypass restrictions on traffic routing that otherwise separate trusted and untrusted networks.",
        "sub-techniques": [
            {
                "sub-technique": "Network Address Translation Traversal",
                "id": "T1599.001",
                "link": "https://attack.mitre.org/techniques/T1599/001",
                "description": "Adversaries may bridge network boundaries by modifying a network device’s Network Address Translation (NAT) configuration. Malicious modifications to NAT may enable an adversary to bypass restrictions on traffic routing that otherwise separate trusted and untrusted networks."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Credential Access Protection",
                "id": "M1043",
                "link": "https://attack.mitre.org/mitigations/M1043",
                "description": "Use capabilities to prevent successful credential access by adversaries; including blocking forms of credential dumping."
            },
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            },
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            }
        ]
    },
    {
        "technique": "Obfuscated Files or Information",
        "id": "T1027",
        "link": "https://attack.mitre.org/techniques/T1027",
        "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.",
        "sub-techniques": [
            {
                "sub-technique": "Binary Padding",
                "id": "T1027.001",
                "link": "https://attack.mitre.org/techniques/T1027/001",
                "description": "Adversaries may use binary padding to add junk data and change the on-disk representation of malware. This can be done without affecting the functionality or behavior of a binary, but can increase the size of the binary beyond what some security tools are capable of handling due to file size limitations."
            },
            {
                "sub-technique": "Steganography",
                "id": "T1027.003",
                "link": "https://attack.mitre.org/techniques/T1027/003",
                "description": "Adversaries may use steganography techniques in order to prevent the detection of hidden information. Steganographic techniques can be used to hide data in digital media such as images, audio tracks, video clips, or text files."
            },
            {
                "sub-technique": "Indicator Removal from Tools",
                "id": "T1027.005",
                "link": "https://attack.mitre.org/techniques/T1027/005",
                "description": "Adversaries may remove indicators from tools if they believe their malicious tool was detected, quarantined, or otherwise curtailed. They can modify the tool by removing the indicator and using the updated version that is no longer detected by the target's defensive systems or subsequent targets that may use similar systems."
            },
            {
                "sub-technique": "Dynamic API Resolution",
                "id": "T1027.007",
                "link": "https://attack.mitre.org/techniques/T1027/007",
                "description": "Adversaries may obfuscate then dynamically resolve API functions called by their malware in order to conceal malicious functionalities and impair defensive analysis. Malware commonly uses various Native API functions provided by the OS to perform various tasks such as those involving processes, files, and other system artifacts."
            },
            {
                "sub-technique": "Embedded Payloads",
                "id": "T1027.009",
                "link": "https://attack.mitre.org/techniques/T1027/009",
                "description": "Adversaries may embed payloads within other files to conceal malicious content from defenses. Otherwise seemingly benign files (such as scripts and executables) may be abused to carry and obfuscate malicious payloads and content. In some cases, embedded payloads may also enable adversaries to Subvert Trust Controls by not impacting execution controls such as digital signatures and notarization tickets."
            },
            {
                "sub-technique": "Fileless Storage",
                "id": "T1027.011",
                "link": "https://attack.mitre.org/techniques/T1027/011",
                "description": "Adversaries may store data in \"fileless\" formats to conceal malicious activity from defenses. Fileless storage can be broadly defined as any format other than a file. Common examples of non-volatile fileless storage include the Windows Registry, event logs, or WMI repository."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Antivirus/Antimalware",
                "id": "M1049",
                "link": "https://attack.mitre.org/mitigations/M1049",
                "description": "Use signatures or heuristics to detect malicious software."
            },
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            }
        ]
    },
    {
        "technique": "Plist File Modification",
        "id": "T1647",
        "link": "https://attack.mitre.org/techniques/T1647",
        "description": "Adversaries may modify property list files (plist files) to enable other malicious activity, while also potentially evading and bypassing system defenses. macOS applications use plist files, such as the info.plist file, to store properties and configuration settings that inform the operating system how to handle the application at runtime. Plist files are structured metadata in key-value pairs formatted in XML based on Apple's Core Foundation DTD. Plist files can be saved in text or binary format.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Application Developer Guidance",
                "id": "M1013",
                "link": "https://attack.mitre.org/mitigations/M1013",
                "description": "This mitigation describes any guidance or training given to developers of applications to avoid introducing security weaknesses that an adversary may be able to take advantage of."
            }
        ]
    },
    {
        "technique": "Pre-OS Boot",
        "id": "T1542",
        "link": "https://attack.mitre.org/techniques/T1542",
        "description": "Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence on a system. During the booting process of a computer, firmware and various startup services are loaded before the operating system. These programs control flow of execution before the operating system takes control.",
        "sub-techniques": [
            {
                "sub-technique": "System Firmware",
                "id": "T1542.001",
                "link": "https://attack.mitre.org/techniques/T1542/001",
                "description": "Adversaries may modify system firmware to persist on systems.The BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) or Extensible Firmware Interface (EFI) are examples of system firmware that operate as the software interface between the operating system and hardware of a computer."
            },
            {
                "sub-technique": "Bootkit",
                "id": "T1542.003",
                "link": "https://attack.mitre.org/techniques/T1542/003",
                "description": "Adversaries may use bootkits to persist on systems. Bootkits reside at a layer below the operating system and may make it difficult to perform full remediation unless an organization suspects one was used and can act accordingly."
            },
            {
                "sub-technique": "TFTP Boot",
                "id": "T1542.005",
                "link": "https://attack.mitre.org/techniques/T1542/005",
                "description": "Adversaries may abuse netbooting to load an unauthorized network device operating system from a Trivial File Transfer Protocol (TFTP) server. TFTP boot (netbooting) is commonly used by network administrators to load configuration-controlled network device images from a centralized management server. Netbooting is one option in the boot sequence and can be used to centralize, manage, and control device images."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Boot Integrity",
                "id": "M1046",
                "link": "https://attack.mitre.org/mitigations/M1046",
                "description": "Use secure methods to boot a system and verify the integrity of the operating system and loading mechanisms."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            }
        ]
    },
    {
        "technique": "Process Injection",
        "id": "T1055",
        "link": "https://attack.mitre.org/techniques/T1055",
        "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process.",
        "sub-techniques": [
            {
                "sub-technique": "Dynamic-link Library Injection",
                "id": "T1055.001",
                "link": "https://attack.mitre.org/techniques/T1055/001",
                "description": "Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges. DLL injection is a method of executing arbitrary code in the address space of a separate live process."
            },
            {
                "sub-technique": "Thread Execution Hijacking",
                "id": "T1055.003",
                "link": "https://attack.mitre.org/techniques/T1055/003",
                "description": "Adversaries may inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. Thread Execution Hijacking is a method of executing arbitrary code in the address space of a separate live process."
            },
            {
                "sub-technique": "Thread Local Storage",
                "id": "T1055.005",
                "link": "https://attack.mitre.org/techniques/T1055/005",
                "description": "Adversaries may inject malicious code into processes via thread local storage (TLS) callbacks in order to evade process-based defenses as well as possibly elevate privileges. TLS callback injection is a method of executing arbitrary code in the address space of a separate live process."
            },
            {
                "sub-technique": "Proc Memory",
                "id": "T1055.009",
                "link": "https://attack.mitre.org/techniques/T1055/009",
                "description": "Adversaries may inject malicious code into processes via the /proc filesystem in order to evade process-based defenses as well as possibly elevate privileges. Proc memory injection is a method of executing arbitrary code in the address space of a separate live process."
            },
            {
                "sub-technique": "Process Hollowing",
                "id": "T1055.012",
                "link": "https://attack.mitre.org/techniques/T1055/012",
                "description": "Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. Process hollowing is a method of executing arbitrary code in the address space of a separate live process."
            },
            {
                "sub-technique": "VDSO Hijacking",
                "id": "T1055.014",
                "link": "https://attack.mitre.org/techniques/T1055/014",
                "description": "Adversaries may inject malicious code into processes via VDSO hijacking in order to evade process-based defenses as well as possibly elevate privileges. Virtual dynamic shared object (vdso) hijacking is a method of executing arbitrary code in the address space of a separate live process."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            }
        ]
    },
    {
        "technique": "Reflective Code Loading",
        "id": "T1620",
        "link": "https://attack.mitre.org/techniques/T1620",
        "description": "Adversaries may reflectively load code into a process in order to conceal the execution of malicious payloads. Reflective loading involves allocating then executing payloads directly within the memory of the process, vice creating a thread or process backed by a file path on disk. Reflectively loaded payloads may be compiled binaries, anonymous files (only present in RAM), or just snubs of fileless executable code (ex: position-independent shellcode).",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Rogue Domain Controller",
        "id": "T1207",
        "link": "https://attack.mitre.org/techniques/T1207",
        "description": "Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data. DCShadow may be used to create a rogue Domain Controller (DC). DCShadow is a method of manipulating Active Directory (AD) data, including objects and schemas, by registering (or reusing an inactive registration) and simulating the behavior of a DC.  Once registered, a rogue DC may be able to inject and replicate changes into AD infrastructure for any domain object, including credentials and keys.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Rootkit",
        "id": "T1014",
        "link": "https://attack.mitre.org/techniques/T1014",
        "description": "Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components. Rootkits are programs that hide the existence of malware by intercepting/hooking and modifying operating system API calls that supply system information.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Subvert Trust Controls",
        "id": "T1553",
        "link": "https://attack.mitre.org/techniques/T1553",
        "description": "Adversaries may undermine security controls that will either warn users of untrusted activity or prevent execution of untrusted programs. Operating systems and security products may contain mechanisms to identify programs or websites as possessing some level of trust. Examples of such features would include a program being allowed to run because it is signed by a valid code signing certificate, a program prompting the user with a warning because it has an attribute set from being downloaded from the Internet, or getting an indication that you are about to connect to an untrusted site.",
        "sub-techniques": [
            {
                "sub-technique": "Gatekeeper Bypass",
                "id": "T1553.001",
                "link": "https://attack.mitre.org/techniques/T1553/001",
                "description": "Adversaries may modify file attributes and subvert Gatekeeper functionality to evade user prompts and execute untrusted programs. Gatekeeper is a set of technologies that act as layer of Apple’s security model to ensure only trusted applications are executed on a host. Gatekeeper was built on top of File Quarantine in Snow Leopard (10.6, 2009) and has grown to include Code Signing, security policy compliance, Notarization, and more. Gatekeeper also treats applications running for the first time differently than reopened applications."
            },
            {
                "sub-technique": "SIP and Trust Provider Hijacking",
                "id": "T1553.003",
                "link": "https://attack.mitre.org/techniques/T1553/003",
                "description": "Adversaries may tamper with SIP and trust provider components to mislead the operating system and application control tools when conducting signature validation checks. In user mode, Windows Authenticode  digital signatures are used to verify a file's origin and integrity, variables that may be used to establish trust in signed code (ex: a driver with a valid Microsoft signature may be handled as safe). The signature validation process is handled via the WinVerifyTrust application programming interface (API) function,   which accepts an inquiry and coordinates with the appropriate trust provider, which is responsible for validating parameters of a signature."
            },
            {
                "sub-technique": "Mark-of-the-Web Bypass",
                "id": "T1553.005",
                "link": "https://attack.mitre.org/techniques/T1553/005",
                "description": "Adversaries may abuse specific file formats to subvert Mark-of-the-Web (MOTW) controls. In Windows, when files are downloaded from the Internet, they are tagged with a hidden NTFS Alternate Data Stream (ADS) named Zone.Identifier with a specific value known as the MOTW. Files that are tagged with MOTW are protected and cannot perform certain actions. For example, starting in MS Office 10, if a MS Office file has the MOTW, it will open in Protected View. Executables tagged with the MOTW will be processed by Windows Defender SmartScreen that compares files with an allowlist of well-known executables. If the file is not known/trusted, SmartScreen will prevent the execution and warn the user not to run it."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            },
            {
                "mitigation": "Restrict Registry Permissions",
                "id": "M1024",
                "link": "https://attack.mitre.org/mitigations/M1024",
                "description": "Restrict the ability to modify certain hives or keys in the Windows Registry."
            },
            {
                "mitigation": "Software Configuration",
                "id": "M1054",
                "link": "https://attack.mitre.org/mitigations/M1054",
                "description": "Implement configuration changes to software (other than the operating system) to mitigate security risks associated to how the software operates."
            }
        ]
    },
    {
        "technique": "System Binary Proxy Execution",
        "id": "T1218",
        "link": "https://attack.mitre.org/techniques/T1218",
        "description": "Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries. Binaries used in this technique are often Microsoft-signed files, indicating that they have been either downloaded from Microsoft or are already native in the operating system. Binaries signed with trusted digital certificates can typically execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files or commands.",
        "sub-techniques": [
            {
                "sub-technique": "Compiled HTML File",
                "id": "T1218.001",
                "link": "https://attack.mitre.org/techniques/T1218/001",
                "description": "Adversaries may abuse Compiled HTML files (.chm) to conceal malicious code. CHM files are commonly distributed as part of the Microsoft HTML Help system. CHM files are compressed compilations of various content such as HTML documents, images, and scripting/web related programming languages such VBA, JScript, Java, and ActiveX.  CHM content is displayed using underlying components of the Internet Explorer browser  loaded by the HTML Help executable program (hh.exe)."
            },
            {
                "sub-technique": "CMSTP",
                "id": "T1218.003",
                "link": "https://attack.mitre.org/techniques/T1218/003",
                "description": "Adversaries may abuse CMSTP to proxy execution of malicious code. The Microsoft Connection Manager Profile Installer (CMSTP.exe) is a command-line program used to install Connection Manager service profiles.  CMSTP.exe accepts an installation information file (INF) as a parameter and installs a service profile leveraged for remote access connections."
            },
            {
                "sub-technique": "Mshta",
                "id": "T1218.005",
                "link": "https://attack.mitre.org/techniques/T1218/005",
                "description": "Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility. There are several examples of different types of threats leveraging mshta.exe during initial compromise and for execution of code"
            },
            {
                "sub-technique": "Odbcconf",
                "id": "T1218.008",
                "link": "https://attack.mitre.org/techniques/T1218/008",
                "description": "Adversaries may abuse odbcconf.exe to proxy execution of malicious payloads. Odbcconf.exe is a Windows utility that allows you to configure Open Database Connectivity (ODBC) drivers and data source names. The Odbcconf.exe binary may be digitally signed by Microsoft."
            },
            {
                "sub-technique": "Regsvr32",
                "id": "T1218.010",
                "link": "https://attack.mitre.org/techniques/T1218/010",
                "description": "Adversaries may abuse Regsvr32.exe to proxy execution of malicious code. Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. The Regsvr32.exe binary may also be signed by Microsoft."
            },
            {
                "sub-technique": "Verclsid",
                "id": "T1218.012",
                "link": "https://attack.mitre.org/techniques/T1218/012",
                "description": "Adversaries may abuse verclsid.exe to proxy execution of malicious code. Verclsid.exe is known as the Extension CLSID Verification Host and is responsible for verifying each shell extension before they are used by Windows Explorer or the Windows Shell."
            },
            {
                "sub-technique": "MMC",
                "id": "T1218.014",
                "link": "https://attack.mitre.org/techniques/T1218/014",
                "description": "Adversaries may abuse mmc.exe to proxy execution of malicious .msc files. Microsoft Management Console (MMC) is a binary that may be signed by Microsoft and is used in several ways in either its GUI or in a command prompt. MMC can be used to create, open, and save custom consoles that contain administrative tools created by Microsoft, called snap-ins. These snap-ins may be used to manage Windows systems locally or remotely. MMC can also be used to open Microsoft created .msc files to manage system configuration."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            },
            {
                "mitigation": "Exploit Protection",
                "id": "M1050",
                "link": "https://attack.mitre.org/mitigations/M1050",
                "description": "Use capabilities to detect and block conditions that may lead to or be indicative of a software exploit occurring."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            }
        ]
    },
    {
        "technique": "System Script Proxy Execution",
        "id": "T1216",
        "link": "https://attack.mitre.org/techniques/T1216",
        "description": "Adversaries may use trusted scripts, often signed with certificates, to proxy the execution of malicious files. Several Microsoft signed scripts that have been downloaded from Microsoft or are default on Windows installations can be used to proxy execution of other files. This behavior may be abused by adversaries to execute malicious files that could bypass application control and signature validation on systems.",
        "sub-techniques": [
            {
                "sub-technique": "PubPrn",
                "id": "T1216.001",
                "link": "https://attack.mitre.org/techniques/T1216/001",
                "description": "Adversaries may use PubPrn to proxy execution of malicious remote files. PubPrn.vbs is a Visual Basic script that publishes a printer to Active Directory Domain Services. The script may be signed by Microsoft and is commonly executed through the Windows Command Shell via Cscript.exe. For example, the following code publishes a printer within the specified domain: cscript pubprn Printer1 LDAP://CN=Container1,DC=Domain1,DC=Com."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            }
        ]
    },
    {
        "technique": "Template Injection",
        "id": "T1221",
        "link": "https://attack.mitre.org/techniques/T1221",
        "description": "Adversaries may create or modify references in user document templates to conceal malicious code or force authentication attempts. For example, Microsoft’s Office Open XML (OOXML) specification defines an XML-based format for Office documents (.docx, xlsx, .pptx) to replace older binary formats (.doc, .xls, .ppt). OOXML files are packed together ZIP archives compromised of various XML files, referred to as parts, containing properties that collectively define how a document is rendered.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Antivirus/Antimalware",
                "id": "M1049",
                "link": "https://attack.mitre.org/mitigations/M1049",
                "description": "Use signatures or heuristics to detect malicious software."
            },
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    },
    {
        "technique": "Traffic Signaling",
        "id": "T1205",
        "link": "https://attack.mitre.org/techniques/T1205",
        "description": "Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control. Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port or executing a malicious task. This may take the form of sending a series of packets with certain characteristics before a port will be opened that the adversary can use for command and control. Usually this series of packets consists of attempted connections to a predefined sequence of closed ports (i.e. Port Knocking), but can involve unusual flags, specific strings, or other unique characteristics. After the sequence is completed, opening a port may be accomplished by the host-based firewall, but could also be implemented by custom software.",
        "sub-techniques": [
            {
                "sub-technique": "Port Knocking",
                "id": "T1205.001",
                "link": "https://attack.mitre.org/techniques/T1205/001",
                "description": "Adversaries may use port knocking to hide open ports used for persistence or command and control. To enable a port, an adversary sends a series of attempted connections to a predefined sequence of closed ports. After the sequence is completed, opening a port is often accomplished by the host based firewall, but could also be implemented by custom software."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            }
        ]
    },
    {
        "technique": "Trusted Developer Utilities Proxy Execution",
        "id": "T1127",
        "link": "https://attack.mitre.org/techniques/T1127",
        "description": "Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads. There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering. These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application control solutions.",
        "sub-techniques": [
            {
                "sub-technique": "MSBuild",
                "id": "T1127.001",
                "link": "https://attack.mitre.org/techniques/T1127/001",
                "description": "Adversaries may use MSBuild to proxy execution of code through a trusted Windows utility. MSBuild.exe (Microsoft Build Engine) is a software build platform used by Visual Studio. It handles XML formatted project files that define requirements for loading and building various platforms and configurations."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            }
        ]
    },
    {
        "technique": "Unused/Unsupported Cloud Regions",
        "id": "T1535",
        "link": "https://attack.mitre.org/techniques/T1535",
        "description": "Adversaries may create cloud instances in unused geographic service regions in order to evade detection. Access is usually obtained through compromising accounts used to manage cloud infrastructure.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Software Configuration",
                "id": "M1054",
                "link": "https://attack.mitre.org/mitigations/M1054",
                "description": "Implement configuration changes to software (other than the operating system) to mitigate security risks associated to how the software operates."
            }
        ]
    },
    {
        "technique": "Use Alternate Authentication Material",
        "id": "T1550",
        "link": "https://attack.mitre.org/techniques/T1550",
        "description": "Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls.",
        "sub-techniques": [
            {
                "sub-technique": "Application Access Token",
                "id": "T1550.001",
                "link": "https://attack.mitre.org/techniques/T1550/001",
                "description": "Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems. These tokens are typically stolen from users or services and used in lieu of login credentials."
            },
            {
                "sub-technique": "Pass the Ticket",
                "id": "T1550.003",
                "link": "https://attack.mitre.org/techniques/T1550/003",
                "description": "Adversaries may \"pass the ticket\" using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls. Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having access to an account's password. Kerberos authentication can be used as the first step to lateral movement to a remote system."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Valid Accounts",
        "id": "T1078",
        "link": "https://attack.mitre.org/techniques/T1078",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access, network devices, and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.",
        "sub-techniques": [
            {
                "sub-technique": "Default Accounts",
                "id": "T1078.001",
                "link": "https://attack.mitre.org/techniques/T1078/001",
                "description": "Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems. Default accounts also include default factory/provider set accounts on other types of systems, software, or devices, including the root user account in AWS and the default service account in Kubernetes."
            },
            {
                "sub-technique": "Local Accounts",
                "id": "T1078.003",
                "link": "https://attack.mitre.org/techniques/T1078/003",
                "description": "Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Account Use Policies",
                "id": "M1036",
                "link": "https://attack.mitre.org/mitigations/M1036",
                "description": "Configure features related to account use like login attempt lockouts, specific login times, etc."
            },
            {
                "mitigation": "Active Directory Configuration",
                "id": "M1015",
                "link": "https://attack.mitre.org/mitigations/M1015",
                "description": "Configure Active Directory to prevent use of certain techniques; use SID Filtering, etc."
            },
            {
                "mitigation": "Application Developer Guidance",
                "id": "M1013",
                "link": "https://attack.mitre.org/mitigations/M1013",
                "description": "This mitigation describes any guidance or training given to developers of applications to avoid introducing security weaknesses that an adversary may be able to take advantage of."
            },
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    },
    {
        "technique": "Virtualization/Sandbox Evasion",
        "id": "T1497",
        "link": "https://attack.mitre.org/techniques/T1497",
        "description": "Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors.",
        "sub-techniques": [
            {
                "sub-technique": "System Checks",
                "id": "T1497.001",
                "link": "https://attack.mitre.org/techniques/T1497/001",
                "description": "Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors."
            },
            {
                "sub-technique": "Time Based Evasion",
                "id": "T1497.003",
                "link": "https://attack.mitre.org/techniques/T1497/003",
                "description": "Adversaries may employ various time-based methods to detect and avoid virtualization and analysis environments. This may include enumerating time-based properties, such as uptime or the system clock, as well as the use of timers or other triggers to avoid a virtual machine environment (VME) or sandbox, specifically those that are automated or only operate for a limited amount of time."
            }
        ],
        "mitigations": []
    },
    {
        "technique": "Weaken Encryption",
        "id": "T1600",
        "link": "https://attack.mitre.org/techniques/T1600",
        "description": "Adversaries may compromise a network device’s encryption capability in order to bypass encryption that would otherwise protect data communications.",
        "sub-techniques": [
            {
                "sub-technique": "Reduce Key Space",
                "id": "T1600.001",
                "link": "https://attack.mitre.org/techniques/T1600/001",
                "description": "Adversaries may reduce the level of effort required to decrypt data transmitted over the network by reducing the cipher strength of encrypted communications."
            }
        ],
        "mitigations": []
    },
    {
        "technique": "XSL Script Processing",
        "id": "T1220",
        "link": "https://attack.mitre.org/techniques/T1220",
        "description": "Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files. Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files. To support complex operations, the XSL standard includes support for embedded scripting in various languages.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            }
        ]
    }
]

credential_access = [
    {
        "technique": "Adversary-in-the-Middle",
        "id": "T1557",
        "link": "https://attack.mitre.org/techniques/T1557",
        "description": "Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation. By abusing features of common networking protocols that can determine the flow of network traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to communicate through an adversary controlled system so they can collect information or perform additional actions.",
        "sub-techniques": [
            {
                "sub-technique": "LLMNR/NBT-NS Poisoning and SMB Relay",
                "id": "T1557.001",
                "link": "https://attack.mitre.org/techniques/T1557/001",
                "description": "By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials."
            },
            {
                "sub-technique": "DHCP Spoofing",
                "id": "T1557.003",
                "link": "https://attack.mitre.org/techniques/T1557/003",
                "description": "Adversaries may redirect network traffic to adversary-owned systems by spoofing Dynamic Host Configuration Protocol (DHCP) traffic and acting as a malicious DHCP server on the victim network. By achieving the adversary-in-the-middle (AiTM) position, adversaries may collect network communications, including passed credentials, especially those sent over insecure, unencrypted protocols. This may also enable follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Encrypt Sensitive Information",
                "id": "M1041",
                "link": "https://attack.mitre.org/mitigations/M1041",
                "description": "Protect sensitive information with strong encryption."
            },
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            },
            {
                "mitigation": "Limit Access to Resource Over Network",
                "id": "M1035",
                "link": "https://attack.mitre.org/mitigations/M1035",
                "description": "Prevent access to file shares, remote access to systems, unnecessary services. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc."
            },
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    },
    {
        "technique": "Brute Force",
        "id": "T1110",
        "link": "https://attack.mitre.org/techniques/T1110",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism. Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as password hashes.",
        "sub-techniques": [
            {
                "sub-technique": "Password Guessing",
                "id": "T1110.001",
                "link": "https://attack.mitre.org/techniques/T1110/001",
                "description": "Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism. An adversary may guess login credentials without prior knowledge of system or environment passwords during an operation by using a list of common passwords. Password guessing may or may not take into account the target's policies on password complexity or use policies that may lock accounts out after a number of failed attempts."
            },
            {
                "sub-technique": "Password Spraying",
                "id": "T1110.003",
                "link": "https://attack.mitre.org/techniques/T1110/003",
                "description": "Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. 'Password01'), or a small list of commonly used passwords, that may match the complexity policy of the domain. Logins are attempted with that password against many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Account Use Policies",
                "id": "M1036",
                "link": "https://attack.mitre.org/mitigations/M1036",
                "description": "Configure features related to account use like login attempt lockouts, specific login times, etc."
            },
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Credentials from Password Stores",
        "id": "T1555",
        "link": "https://attack.mitre.org/techniques/T1555",
        "description": "Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in several places on a system, depending on the operating system or application holding the credentials. There are also specific applications that store passwords to make it easier for users manage and maintain. Once credentials are obtained, they can be used to perform lateral movement and access restricted information.",
        "sub-techniques": [
            {
                "sub-technique": "Keychain",
                "id": "T1555.001",
                "link": "https://attack.mitre.org/techniques/T1555/001",
                "description": "Adversaries may acquire credentials from Keychain. Keychain (or Keychain Services) is the macOS credential management system that stores account names, passwords, private keys, certificates, sensitive application data, payment data, and secure notes. There are three types of Keychains: Login Keychain, System Keychain, and Local Items (iCloud) Keychain. The default Keychain is the Login Keychain, which stores user passwords and information. The System Keychain stores items accessed by the operating system, such as items shared among users on a host. The Local Items (iCloud) Keychain is used for items synced with Apple’s iCloud service."
            },
            {
                "sub-technique": "Credentials from Web Browsers",
                "id": "T1555.003",
                "link": "https://attack.mitre.org/techniques/T1555/003",
                "description": "Adversaries may acquire credentials from web browsers by reading files specific to the target browser. Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future. Web browsers typically store the credentials in an encrypted format within a credential store; however, methods exist to extract plaintext credentials from web browsers."
            },
            {
                "sub-technique": "Password Managers",
                "id": "T1555.005",
                "link": "https://attack.mitre.org/techniques/T1555/005",
                "description": "Adversaries may acquire user credentials from third-party password managers. Password managers are applications designed to store user credentials, normally in an encrypted database. Credentials are typically accessible after a user provides a master password that unlocks the database. After the database is unlocked, these credentials may be copied to memory. These databases can be stored as files on disk."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            }
        ]
    },
    {
        "technique": "Exploitation for Credential Access",
        "id": "T1212",
        "link": "https://attack.mitre.org/techniques/T1212",
        "description": "Adversaries may exploit software vulnerabilities in an attempt to collect credentials. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Credentialing and authentication mechanisms may be targeted for exploitation by adversaries as a means to gain access to useful credentials or circumvent the process to gain access to systems. One example of this is MS14-068, which targets Kerberos and can be used to forge Kerberos tickets using domain user permissions. Exploitation for credential access may also result in Privilege Escalation depending on the process targeted or credentials obtained.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Application Isolation and Sandboxing",
                "id": "M1048",
                "link": "https://attack.mitre.org/mitigations/M1048",
                "description": "Restrict execution of code to a virtual environment on or in transit to an endpoint system."
            },
            {
                "mitigation": "Exploit Protection",
                "id": "M1050",
                "link": "https://attack.mitre.org/mitigations/M1050",
                "description": "Use capabilities to detect and block conditions that may lead to or be indicative of a software exploit occurring."
            },
            {
                "mitigation": "Threat Intelligence Program",
                "id": "M1019",
                "link": "https://attack.mitre.org/mitigations/M1019",
                "description": "A threat intelligence program helps an organization generate their own threat intelligence information and track trends to inform defensive priorities to mitigate risk."
            },
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            }
        ]
    },
    {
        "technique": "Forced Authentication",
        "id": "T1187",
        "link": "https://attack.mitre.org/techniques/T1187",
        "description": "Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            },
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            }
        ]
    },
    {
        "technique": "Forge Web Credentials",
        "id": "T1606",
        "link": "https://attack.mitre.org/techniques/T1606",
        "description": "Adversaries may forge credential materials that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies, tokens, or other materials to authenticate and authorize user access.",
        "sub-techniques": [
            {
                "sub-technique": "Web Cookies",
                "id": "T1606.001",
                "link": "https://attack.mitre.org/techniques/T1606/001",
                "description": "Adversaries may forge web cookies that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies to authenticate and authorize user access."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Software Configuration",
                "id": "M1054",
                "link": "https://attack.mitre.org/mitigations/M1054",
                "description": "Implement configuration changes to software (other than the operating system) to mitigate security risks associated to how the software operates."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Input Capture",
        "id": "T1056",
        "link": "https://attack.mitre.org/techniques/T1056",
        "description": "Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. Credential API Hooking) or rely on deceiving the user into providing input into what they believe to be a genuine service (e.g. Web Portal Capture).",
        "sub-techniques": [
            {
                "sub-technique": "Keylogging",
                "id": "T1056.001",
                "link": "https://attack.mitre.org/techniques/T1056/001",
                "description": "Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when OS Credential Dumping efforts are not effective, and may require an adversary to intercept keystrokes on a system for a substantial period of time before credentials can be successfully captured."
            },
            {
                "sub-technique": "Web Portal Capture",
                "id": "T1056.003",
                "link": "https://attack.mitre.org/techniques/T1056/003",
                "description": "Adversaries may install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. For example, a compromised login page may log provided user credentials before logging the user in to the service."
            }
        ],
        "mitigations": []
    },
    {
        "technique": "Modify Authentication Process",
        "id": "T1556",
        "link": "https://attack.mitre.org/techniques/T1556",
        "description": "Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials. By modifying an authentication process, an adversary may be able to authenticate to a service or system without using Valid Accounts.",
        "sub-techniques": [
            {
                "sub-technique": "Domain Controller Authentication",
                "id": "T1556.001",
                "link": "https://attack.mitre.org/techniques/T1556/001",
                "description": "Adversaries may patch the authentication process on a domain controller to bypass the typical authentication mechanisms and enable access to accounts."
            },
            {
                "sub-technique": "Pluggable Authentication Modules",
                "id": "T1556.003",
                "link": "https://attack.mitre.org/techniques/T1556/003",
                "description": "Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts. PAM is a modular system of configuration files, libraries, and executable files which guide authentication for many services. The most common authentication module is pam_unix.so, which retrieves, sets, and verifies account authentication information in /etc/passwd and /etc/shadow."
            },
            {
                "sub-technique": "Reversible Encryption",
                "id": "T1556.005",
                "link": "https://attack.mitre.org/techniques/T1556/005",
                "description": "An adversary may abuse Active Directory authentication encryption properties to gain access to credentials on Windows systems. The AllowReversiblePasswordEncryption property specifies whether reversible password encryption for an account is enabled or disabled. By default this property is disabled (instead storing user credentials as the output of one-way hashing functions) and should not be enabled unless legacy or other software require it."
            },
            {
                "sub-technique": "Hybrid Identity",
                "id": "T1556.007",
                "link": "https://attack.mitre.org/techniques/T1556/007",
                "description": "Adversaries may patch, modify, or otherwise backdoor cloud authentication processes that are tied to on-premises user identities in order to bypass typical authentication mechanisms, access credentials, and enable persistent access to accounts."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            },
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Privileged Process Integrity",
                "id": "M1025",
                "link": "https://attack.mitre.org/mitigations/M1025",
                "description": "Protect processes with high privileges that can be used to interact with critical system components through use of protected process light, anti-process injection defenses, or other process integrity enforcement measures."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            },
            {
                "mitigation": "Restrict Registry Permissions",
                "id": "M1024",
                "link": "https://attack.mitre.org/mitigations/M1024",
                "description": "Restrict the ability to modify certain hives or keys in the Windows Registry."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Multi-Factor Authentication Interception",
        "id": "T1111",
        "link": "https://attack.mitre.org/techniques/T1111",
        "description": "Adversaries may target multi-factor authentication (MFA) mechanisms, (i.e., smart cards, token generators, etc.) to gain access to credentials that can be used to access systems, services, and network resources. Use of MFA is recommended and provides a higher level of security than usernames and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    },
    {
        "technique": "Multi-Factor Authentication Request Generation",
        "id": "T1621",
        "link": "https://attack.mitre.org/techniques/T1621",
        "description": "Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms and gain access to accounts by generating MFA requests sent to users.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Account Use Policies",
                "id": "M1036",
                "link": "https://attack.mitre.org/mitigations/M1036",
                "description": "Configure features related to account use like login attempt lockouts, specific login times, etc."
            },
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    },
    {
        "technique": "Network Sniffing",
        "id": "T1040",
        "link": "https://attack.mitre.org/techniques/T1040",
        "description": "Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Encrypt Sensitive Information",
                "id": "M1041",
                "link": "https://attack.mitre.org/mitigations/M1041",
                "description": "Protect sensitive information with strong encryption."
            },
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "OS Credential Dumping",
        "id": "T1003",
        "link": "https://attack.mitre.org/techniques/T1003",
        "description": "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software. Credentials can then be used to perform Lateral Movement and access restricted information.",
        "sub-techniques": [
            {
                "sub-technique": "LSASS Memory",
                "id": "T1003.001",
                "link": "https://attack.mitre.org/techniques/T1003/001",
                "description": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct Lateral Movement using Use Alternate Authentication Material."
            },
            {
                "sub-technique": "NTDS",
                "id": "T1003.003",
                "link": "https://attack.mitre.org/techniques/T1003/003",
                "description": "Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights. By default, the NTDS file (NTDS.dit) is located in %SystemRoot%\\NTDS\\Ntds.dit of a domain controller."
            },
            {
                "sub-technique": "Cached Domain Credentials",
                "id": "T1003.005",
                "link": "https://attack.mitre.org/techniques/T1003/005",
                "description": "Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable."
            },
            {
                "sub-technique": "Proc Filesystem",
                "id": "T1003.007",
                "link": "https://attack.mitre.org/techniques/T1003/007",
                "description": "Adversaries may gather credentials from the proc filesystem or /proc. The proc filesystem is a pseudo-filesystem used as an interface to kernel data structures for Linux based systems managing virtual memory. For each process, the /proc/<PID>/maps file shows how memory is mapped within the process’s virtual address space. And /proc/<PID>/mem, exposed for debugging purposes, provides access to the process’s virtual address space."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Active Directory Configuration",
                "id": "M1015",
                "link": "https://attack.mitre.org/mitigations/M1015",
                "description": "Configure Active Directory to prevent use of certain techniques; use SID Filtering, etc."
            },
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Credential Access Protection",
                "id": "M1043",
                "link": "https://attack.mitre.org/mitigations/M1043",
                "description": "Use capabilities to prevent successful credential access by adversaries; including blocking forms of credential dumping."
            },
            {
                "mitigation": "Encrypt Sensitive Information",
                "id": "M1041",
                "link": "https://attack.mitre.org/mitigations/M1041",
                "description": "Protect sensitive information with strong encryption."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            },
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Privileged Process Integrity",
                "id": "M1025",
                "link": "https://attack.mitre.org/mitigations/M1025",
                "description": "Protect processes with high privileges that can be used to interact with critical system components through use of protected process light, anti-process injection defenses, or other process integrity enforcement measures."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    },
    {
        "technique": "Steal Application Access Token",
        "id": "T1528",
        "link": "https://attack.mitre.org/techniques/T1528",
        "description": "Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Restrict Web-Based Content",
                "id": "M1021",
                "link": "https://attack.mitre.org/mitigations/M1021",
                "description": "Restrict use of certain websites, block downloads/attachments, block Javascript, restrict browser extensions, etc."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    },
    {
        "technique": "Steal or Forge Authentication Certificates",
        "id": "T1649",
        "link": "https://attack.mitre.org/techniques/T1649",
        "description": "Adversaries may steal or forge certificates used for authentication to access remote systems or resources. Digital certificates are often used to sign and encrypt messages and/or files. Certificates are also used as authentication material. For example, Azure AD device certificates and Active Directory Certificate Services (AD CS) certificates bind to an identity and can be used as credentials for domain accounts.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Active Directory Configuration",
                "id": "M1015",
                "link": "https://attack.mitre.org/mitigations/M1015",
                "description": "Configure Active Directory to prevent use of certain techniques; use SID Filtering, etc."
            },
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Encrypt Sensitive Information",
                "id": "M1041",
                "link": "https://attack.mitre.org/mitigations/M1041",
                "description": "Protect sensitive information with strong encryption."
            }
        ]
    },
    {
        "technique": "Steal or Forge Kerberos Tickets",
        "id": "T1558",
        "link": "https://attack.mitre.org/techniques/T1558",
        "description": "Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable Pass the Ticket. Kerberos is an authentication protocol widely used in modern Windows domain environments. In Kerberos environments, referred to as \"realms\", there are three basic participants: client, service, and Key Distribution Center (KDC). Clients request access to a service and through the exchange of Kerberos tickets, originating from KDC, they are granted access after having successfully authenticated. The KDC is responsible for both authentication and ticket granting.  Adversaries may attempt to abuse Kerberos by stealing tickets or forging tickets to enable unauthorized access.",
        "sub-techniques": [
            {
                "sub-technique": "Golden Ticket",
                "id": "T1558.001",
                "link": "https://attack.mitre.org/techniques/T1558/001",
                "description": "Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket. Golden tickets enable adversaries to generate authentication material for any account in Active Directory."
            },
            {
                "sub-technique": "Kerberoasting",
                "id": "T1558.003",
                "link": "https://attack.mitre.org/techniques/T1558/003",
                "description": "Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to Brute Force."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Active Directory Configuration",
                "id": "M1015",
                "link": "https://attack.mitre.org/mitigations/M1015",
                "description": "Configure Active Directory to prevent use of certain techniques; use SID Filtering, etc."
            },
            {
                "mitigation": "Encrypt Sensitive Information",
                "id": "M1041",
                "link": "https://attack.mitre.org/mitigations/M1041",
                "description": "Protect sensitive information with strong encryption."
            },
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            }
        ]
    },
    {
        "technique": "Steal Web Session Cookie",
        "id": "T1539",
        "link": "https://attack.mitre.org/techniques/T1539",
        "description": "An adversary may steal web application or service session cookies and use them to gain access to web applications or Internet services as an authenticated user without needing credentials. Web applications and services often use session cookies as an authentication token after a user has authenticated to a website.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "Software Configuration",
                "id": "M1054",
                "link": "https://attack.mitre.org/mitigations/M1054",
                "description": "Implement configuration changes to software (other than the operating system) to mitigate security risks associated to how the software operates."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    },
    {
        "technique": "Unsecured Credentials",
        "id": "T1552",
        "link": "https://attack.mitre.org/techniques/T1552",
        "description": "Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. Bash History), operating system or application-specific repositories (e.g. Credentials in Registry), or other specialized files/artifacts (e.g. Private Keys).",
        "sub-techniques": [
            {
                "sub-technique": "Credentials In Files",
                "id": "T1552.001",
                "link": "https://attack.mitre.org/techniques/T1552/001",
                "description": "Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords."
            },
            {
                "sub-technique": "Bash History",
                "id": "T1552.003",
                "link": "https://attack.mitre.org/techniques/T1552/003",
                "description": "Adversaries may search the bash command history on compromised systems for insecurely stored credentials. Bash keeps track of the commands users type on the command-line with the \"history\" utility. Once a user logs out, the history is flushed to the user’s .bash_history file. For each user, this file resides at the same location: ~/.bash_history. Typically, this file keeps track of the user’s last 500 commands. Users often type usernames and passwords on the command-line as parameters to programs, which then get saved to this file when they log out. Adversaries can abuse this by looking through the file for potential credentials."
            },
            {
                "sub-technique": "Cloud Instance Metadata API",
                "id": "T1552.005",
                "link": "https://attack.mitre.org/techniques/T1552/005",
                "description": "Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive data."
            },
            {
                "sub-technique": "Container API",
                "id": "T1552.007",
                "link": "https://attack.mitre.org/techniques/T1552/007",
                "description": "Adversaries may gather credentials via APIs within a containers environment. APIs in these environments, such as the Docker API and Kubernetes APIs, allow a user to remotely manage their container resources and cluster components."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Active Directory Configuration",
                "id": "M1015",
                "link": "https://attack.mitre.org/mitigations/M1015",
                "description": "Configure Active Directory to prevent use of certain techniques; use SID Filtering, etc."
            },
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Encrypt Sensitive Information",
                "id": "M1041",
                "link": "https://attack.mitre.org/mitigations/M1041",
                "description": "Protect sensitive information with strong encryption."
            },
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            },
            {
                "mitigation": "Limit Access to Resource Over Network",
                "id": "M1035",
                "link": "https://attack.mitre.org/mitigations/M1035",
                "description": "Prevent access to file shares, remote access to systems, unnecessary services. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            },
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            },
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    }
]

discovery = [
    {
        "technique": "Account Discovery",
        "id": "T1087",
        "link": "https://attack.mitre.org/techniques/T1087",
        "description": "Adversaries may attempt to get a listing of valid accounts, usernames, or email addresses on a system or within a compromised environment. This information can help adversaries determine which accounts exist, which can aid in follow-on behavior such as brute-forcing, spear-phishing attacks, or account takeovers (e.g., Valid Accounts).",
        "sub-techniques": [
            {
                "sub-technique": "Local Account",
                "id": "T1087.001",
                "link": "https://attack.mitre.org/techniques/T1087/001",
                "description": "Adversaries may attempt to get a listing of local system accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior."
            },
            {
                "sub-technique": "Email Account",
                "id": "T1087.003",
                "link": "https://attack.mitre.org/techniques/T1087/003",
                "description": "Adversaries may attempt to get a listing of email addresses and accounts. Adversaries may try to dump Exchange address lists such as global address lists (GALs)."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            }
        ]
    },
    {
        "technique": "Application Window Discovery",
        "id": "T1010",
        "link": "https://attack.mitre.org/techniques/T1010",
        "description": "Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used. For example, information about application windows could be used identify potential data to collect as well as identifying security tooling (Security Software Discovery) to evade.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Browser Information Discovery",
        "id": "T1217",
        "link": "https://attack.mitre.org/techniques/T1217",
        "description": "Adversaries may enumerate information about browsers to learn more about compromised environments. Data saved by browsers (such as bookmarks, accounts, and browsing history) may reveal a variety of personal information about users (e.g., banking sites, relationships/interests, social media, etc.) as well as details about internal network resources such as servers, tools/dashboards, or other related infrastructure.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Cloud Infrastructure Discovery",
        "id": "T1580",
        "link": "https://attack.mitre.org/techniques/T1580",
        "description": "An adversary may attempt to discover infrastructure and resources that are available within an infrastructure-as-a-service (IaaS) environment. This includes compute service resources such as instances, virtual machines, and snapshots as well as resources of other services including the storage and database services.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Cloud Service Dashboard",
        "id": "T1538",
        "link": "https://attack.mitre.org/techniques/T1538",
        "description": "An adversary may use a cloud service dashboard GUI with stolen credentials to gain useful information from an operational cloud environment, such as specific services, resources, and features. For example, the GCP Command Center can be used to view all assets, findings of potential security risks, and to run additional queries, such as finding public IP addresses and open ports.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Cloud Service Discovery",
        "id": "T1526",
        "link": "https://attack.mitre.org/techniques/T1526",
        "description": "An adversary may attempt to enumerate the cloud services running on a system after gaining access. These methods can differ from platform-as-a-service (PaaS), to infrastructure-as-a-service (IaaS), or software-as-a-service (SaaS). Many services exist throughout the various cloud providers and can include Continuous Integration and Continuous Delivery (CI/CD), Lambda Functions, Azure AD, etc. They may also include security services, such as AWS GuardDuty and Microsoft Defender for Cloud, and logging services, such as AWS CloudTrail and Google Cloud Audit Logs.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Cloud Storage Object Discovery",
        "id": "T1619",
        "link": "https://attack.mitre.org/techniques/T1619",
        "description": "Adversaries may enumerate objects in cloud storage infrastructure. Adversaries may use this information during automated discovery to shape follow-on behaviors, including requesting all or specific objects from cloud storage.  Similar to File and Directory Discovery on a local host, after identifying available storage services (i.e. Cloud Infrastructure Discovery) adversaries may access the contents/objects stored in cloud infrastructure.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Container and Resource Discovery",
        "id": "T1613",
        "link": "https://attack.mitre.org/techniques/T1613",
        "description": "Adversaries may attempt to discover containers and other resources that are available within a containers environment. Other resources may include images, deployments, pods, nodes, and other information such as the status of a cluster.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Limit Access to Resource Over Network",
                "id": "M1035",
                "link": "https://attack.mitre.org/mitigations/M1035",
                "description": "Prevent access to file shares, remote access to systems, unnecessary services. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Debugger Evasion",
        "id": "T1622",
        "link": "https://attack.mitre.org/techniques/T1622",
        "description": "Adversaries may employ various means to detect and avoid debuggers. Debuggers are typically used by defenders to trace and/or analyze the execution of potential malware payloads.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Device Driver Discovery",
        "id": "T1652",
        "link": "https://attack.mitre.org/techniques/T1652",
        "description": "Adversaries may attempt to enumerate local device drivers on a victim host. Information about device drivers may highlight various insights that shape follow-on behaviors, such as the function/purpose of the host, present security tools (i.e. Security Software Discovery) or other defenses (e.g., Virtualization/Sandbox Evasion), as well as potential exploitable vulnerabilities (e.g., Exploitation for Privilege Escalation).",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Domain Trust Discovery",
        "id": "T1482",
        "link": "https://attack.mitre.org/techniques/T1482",
        "description": "Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments. Domain trusts provide a mechanism for a domain to allow access to resources based on the authentication procedures of another domain. Domain trusts allow the users of the trusted domain to access resources in the trusting domain. The information discovered may help the adversary conduct SID-History Injection, Pass the Ticket, and Kerberoasting. Domain trusts can be enumerated using the DSEnumerateDomainTrusts() Win32 API call, .NET methods, and LDAP. The Windows utility Nltest is known to be used by adversaries to enumerate domain trusts.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            }
        ]
    },
    {
        "technique": "File and Directory Discovery",
        "id": "T1083",
        "link": "https://attack.mitre.org/techniques/T1083",
        "description": "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from File and Directory Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Group Policy Discovery",
        "id": "T1615",
        "link": "https://attack.mitre.org/techniques/T1615",
        "description": "Adversaries may gather information on Group Policy settings to identify paths for privilege escalation, security measures applied within a domain, and to discover patterns in domain objects that can be manipulated or used to blend in the environment. Group Policy allows for centralized management of user and computer settings in Active Directory (AD). Group policy objects (GPOs) are containers for group policy settings made up of files stored within a predictable network path \\<DOMAIN>\\SYSVOL\\<DOMAIN>\\Policies\\.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Network Service Discovery",
        "id": "T1046",
        "link": "https://attack.mitre.org/techniques/T1046",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port and/or vulnerability scans using tools that are brought onto a system.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            }
        ]
    },
    {
        "technique": "Network Share Discovery",
        "id": "T1135",
        "link": "https://attack.mitre.org/techniques/T1135",
        "description": "Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement. Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            }
        ]
    },
    {
        "technique": "Network Sniffing",
        "id": "T1040",
        "link": "https://attack.mitre.org/techniques/T1040",
        "description": "Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Encrypt Sensitive Information",
                "id": "M1041",
                "link": "https://attack.mitre.org/mitigations/M1041",
                "description": "Protect sensitive information with strong encryption."
            },
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Password Policy Discovery",
        "id": "T1201",
        "link": "https://attack.mitre.org/techniques/T1201",
        "description": "Adversaries may attempt to access detailed information about the password policy used within an enterprise network or cloud environment. Password policies are a way to enforce complex passwords that are difficult to guess or crack through Brute Force. This information may help the adversary to create a list of common passwords and launch dictionary and/or brute force attacks which adheres to the policy (e.g. if the minimum password length should be 8, then not trying passwords such as 'pass123'; not checking for more than 3-4 passwords per account if the lockout is set to 6 as to not lock out accounts).",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            }
        ]
    },
    {
        "technique": "Peripheral Device Discovery",
        "id": "T1120",
        "link": "https://attack.mitre.org/techniques/T1120",
        "description": "Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system. Peripheral devices could include auxiliary resources that support a variety of functionalities such as keyboards, printers, cameras, smart card readers, or removable storage. The information may be used to enhance their awareness of the system and network environment or may be used for further actions.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Permission Groups Discovery",
        "id": "T1069",
        "link": "https://attack.mitre.org/techniques/T1069",
        "description": "Adversaries may attempt to discover group and permission settings. This information can help adversaries determine which user accounts and groups are available, the membership of users in particular groups, and which users and groups have elevated permissions.",
        "sub-techniques": [
            {
                "sub-technique": "Local Groups",
                "id": "T1069.001",
                "link": "https://attack.mitre.org/techniques/T1069/001",
                "description": "Adversaries may attempt to find local system groups and permission settings. The knowledge of local system permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as the users found within the local administrators group."
            },
            {
                "sub-technique": "Cloud Groups",
                "id": "T1069.003",
                "link": "https://attack.mitre.org/techniques/T1069/003",
                "description": "Adversaries may attempt to find cloud groups and permission settings. The knowledge of cloud permission groups can help adversaries determine the particular roles of users and groups within an environment, as well as which users are associated with a particular group."
            }
        ],
        "mitigations": []
    },
    {
        "technique": "Process Discovery",
        "id": "T1057",
        "link": "https://attack.mitre.org/techniques/T1057",
        "description": "Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network. Adversaries may use the information from Process Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Query Registry",
        "id": "T1012",
        "link": "https://attack.mitre.org/techniques/T1012",
        "description": "Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Remote System Discovery",
        "id": "T1018",
        "link": "https://attack.mitre.org/techniques/T1018",
        "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used such as  Ping or net view using Net.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Software Discovery",
        "id": "T1518",
        "link": "https://attack.mitre.org/techniques/T1518",
        "description": "Adversaries may attempt to get a listing of software and software versions that are installed on a system or in a cloud environment. Adversaries may use the information from Software Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
        "sub-techniques": [
            {
                "sub-technique": "Security Software Discovery",
                "id": "T1518.001",
                "link": "https://attack.mitre.org/techniques/T1518/001",
                "description": "Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment. This may include things such as firewall rules and anti-virus. Adversaries may use the information from Security Software Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions."
            }
        ],
        "mitigations": []
    },
    {
        "technique": "System Information Discovery",
        "id": "T1082",
        "link": "https://attack.mitre.org/techniques/T1082",
        "description": "An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use the information from System Information Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "System Location Discovery",
        "id": "T1614",
        "link": "https://attack.mitre.org/techniques/T1614",
        "description": "Adversaries may gather information in an attempt to calculate the geographical location of a victim host. Adversaries may use the information from System Location Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
        "sub-techniques": [
            {
                "sub-technique": "System Language Discovery",
                "id": "T1614.001",
                "link": "https://attack.mitre.org/techniques/T1614/001",
                "description": "Adversaries may attempt to gather information about the system language of a victim in order to infer the geographical location of that host. This information may be used to shape follow-on behaviors, including whether the adversary infects the target and/or attempts specific actions. This decision may be employed by malware developers and operators to reduce their risk of attracting the attention of specific law enforcement agencies or prosecution/scrutiny from other entities."
            }
        ],
        "mitigations": []
    },
    {
        "technique": "System Network Configuration Discovery",
        "id": "T1016",
        "link": "https://attack.mitre.org/techniques/T1016",
        "description": "Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include Arp, ipconfig/ifconfig, nbtstat, and route.",
        "sub-techniques": [
            {
                "sub-technique": "Internet Connection Discovery",
                "id": "T1016.001",
                "link": "https://attack.mitre.org/techniques/T1016/001",
                "description": "Adversaries may check for Internet connectivity on compromised systems. This may be performed during automated discovery and can be accomplished in numerous ways such as using Ping, tracert, and GET requests to websites."
            }
        ],
        "mitigations": []
    },
    {
        "technique": "System Network Connections Discovery",
        "id": "T1049",
        "link": "https://attack.mitre.org/techniques/T1049",
        "description": "Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "System Owner/User Discovery",
        "id": "T1033",
        "link": "https://attack.mitre.org/techniques/T1033",
        "description": "Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using OS Credential Dumping. The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs. Adversaries may use the information from System Owner/User Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "System Service Discovery",
        "id": "T1007",
        "link": "https://attack.mitre.org/techniques/T1007",
        "description": "Adversaries may try to gather information about registered local system services. Adversaries may obtain information about services using tools as well as OS utility commands such as sc query, tasklist /svc, systemctl --type=service, and net start.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "System Time Discovery",
        "id": "T1124",
        "link": "https://attack.mitre.org/techniques/T1124",
        "description": "An adversary may gather the system time and/or time zone from a local or remote system. The system time is set and stored by the Windows Time Service within a domain to maintain time synchronization between systems and services in an enterprise network.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Virtualization/Sandbox Evasion",
        "id": "T1497",
        "link": "https://attack.mitre.org/techniques/T1497",
        "description": "Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors.",
        "sub-techniques": [
            {
                "sub-technique": "System Checks",
                "id": "T1497.001",
                "link": "https://attack.mitre.org/techniques/T1497/001",
                "description": "Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors."
            },
            {
                "sub-technique": "Time Based Evasion",
                "id": "T1497.003",
                "link": "https://attack.mitre.org/techniques/T1497/003",
                "description": "Adversaries may employ various time-based methods to detect and avoid virtualization and analysis environments. This may include enumerating time-based properties, such as uptime or the system clock, as well as the use of timers or other triggers to avoid a virtual machine environment (VME) or sandbox, specifically those that are automated or only operate for a limited amount of time."
            }
        ],
        "mitigations": []
    }
]

lateral_movement = [
    {
        "technique": "Exploitation of Remote Services",
        "id": "T1210",
        "link": "https://attack.mitre.org/techniques/T1210",
        "description": "Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. A common goal for post-compromise exploitation of remote services is for lateral movement to enable access to a remote system.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Application Isolation and Sandboxing",
                "id": "M1048",
                "link": "https://attack.mitre.org/mitigations/M1048",
                "description": "Restrict execution of code to a virtual environment on or in transit to an endpoint system."
            },
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Exploit Protection",
                "id": "M1050",
                "link": "https://attack.mitre.org/mitigations/M1050",
                "description": "Use capabilities to detect and block conditions that may lead to or be indicative of a software exploit occurring."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Threat Intelligence Program",
                "id": "M1019",
                "link": "https://attack.mitre.org/mitigations/M1019",
                "description": "A threat intelligence program helps an organization generate their own threat intelligence information and track trends to inform defensive priorities to mitigate risk."
            },
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            },
            {
                "mitigation": "Vulnerability Scanning",
                "id": "M1016",
                "link": "https://attack.mitre.org/mitigations/M1016",
                "description": "Vulnerability scanning is used to find potentially exploitable software vulnerabilities to remediate them."
            }
        ]
    },
    {
        "technique": "Internal Spearphishing",
        "id": "T1534",
        "link": "https://attack.mitre.org/techniques/T1534",
        "description": "Adversaries may use internal spearphishing to gain access to additional information or exploit other users within the same organization after they already have access to accounts or systems within the environment. Internal spearphishing is multi-staged campaign where an email account is owned either by controlling the user's device with previously installed malware or by compromising the account credentials of the user. Adversaries attempt to take advantage of a trusted internal account to increase the likelihood of tricking the target into falling for the phish attempt.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Lateral Tool Transfer",
        "id": "T1570",
        "link": "https://attack.mitre.org/techniques/T1570",
        "description": "Adversaries may transfer tools or other files between systems in a compromised environment. Once brought into the victim environment (i.e. Ingress Tool Transfer) files may then be copied from one system to another to stage adversary tools or other files over the course of an operation. Adversaries may copy files between internal victim systems to support lateral movement using inherent file sharing protocols such as file sharing over SMB/Windows Admin Shares to connected network shares or with authenticated connections via Remote Desktop Protocol.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            },
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            }
        ]
    },
    {
        "technique": "Remote Service Session Hijacking",
        "id": "T1563",
        "link": "https://attack.mitre.org/techniques/T1563",
        "description": "Adversaries may take control of preexisting sessions with remote services to move laterally in an environment. Users may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP. When a user logs into a service, a session will be established that will allow them to maintain a continuous interaction with that service.",
        "sub-techniques": [
            {
                "sub-technique": "SSH Hijacking",
                "id": "T1563.001",
                "link": "https://attack.mitre.org/techniques/T1563/001",
                "description": "Adversaries may hijack a legitimate user's SSH session to move laterally within an environment. Secure Shell (SSH) is a standard means of remote access on Linux and macOS systems. It allows a user to connect to another system via an encrypted tunnel, commonly authenticating through a password, certificate or the use of an asymmetric encryption key pair."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Remote Services",
        "id": "T1021",
        "link": "https://attack.mitre.org/techniques/T1021",
        "description": "Adversaries may use Valid Accounts to log into a service that accepts remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user.",
        "sub-techniques": [
            {
                "sub-technique": "Remote Desktop Protocol",
                "id": "T1021.001",
                "link": "https://attack.mitre.org/techniques/T1021/001",
                "description": "Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user."
            },
            {
                "sub-technique": "Distributed Component Object Model",
                "id": "T1021.003",
                "link": "https://attack.mitre.org/techniques/T1021/003",
                "description": "Adversaries may use Valid Accounts to interact with remote machines by taking advantage of Distributed Component Object Model (DCOM). The adversary may then perform actions as the logged-on user."
            },
            {
                "sub-technique": "VNC",
                "id": "T1021.005",
                "link": "https://attack.mitre.org/techniques/T1021/005",
                "description": "Adversaries may use Valid Accounts to remotely control machines using Virtual Network Computing (VNC).  VNC is a platform-independent desktop sharing system that uses the RFB (\"remote framebuffer\") protocol to enable users to remotely control another computer’s display by relaying the screen, mouse, and keyboard inputs over the network."
            },
            {
                "sub-technique": "Cloud Services",
                "id": "T1021.007",
                "link": "https://attack.mitre.org/techniques/T1021/007",
                "description": "Adversaries may log into accessible cloud services within a compromised environment using Valid Accounts that are synchronized with or federated to on-premises user identities. The adversary may then perform management actions or access cloud-hosted resources as the logged-on user."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Replication Through Removable Media",
        "id": "T1091",
        "link": "https://attack.mitre.org/techniques/T1091",
        "description": "Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes. In the case of Lateral Movement, this may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system. In the case of Initial Access, this may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Limit Hardware Installation",
                "id": "M1034",
                "link": "https://attack.mitre.org/mitigations/M1034",
                "description": "Block users or groups from installing or using unapproved hardware on systems, including USB devices."
            }
        ]
    },
    {
        "technique": "Software Deployment Tools",
        "id": "T1072",
        "link": "https://attack.mitre.org/techniques/T1072",
        "description": "Adversaries may gain access to and use third-party software suites installed within an enterprise network, such as administration, monitoring, and deployment systems, to move laterally through the network. Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, HBSS, Altiris, etc.).",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Active Directory Configuration",
                "id": "M1015",
                "link": "https://attack.mitre.org/mitigations/M1015",
                "description": "Configure Active Directory to prevent use of certain techniques; use SID Filtering, etc."
            },
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            },
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Remote Data Storage",
                "id": "M1029",
                "link": "https://attack.mitre.org/mitigations/M1029",
                "description": "Use remote security log and sensitive file storage where access can be controlled better to prevent exposure of intrusion detection log data or sensitive information."
            },
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    },
    {
        "technique": "Taint Shared Content",
        "id": "T1080",
        "link": "https://attack.mitre.org/techniques/T1080",
        "description": "Adversaries may deliver payloads to remote systems by adding content to shared storage locations, such as network drives or internal code repositories. Content stored on network drives or in other shared locations may be tainted by adding malicious programs, scripts, or exploit code to otherwise valid files. Once a user opens the shared tainted content, the malicious portion can be executed to run the adversary's code on a remote system. Adversaries may use tainted shared content to move laterally.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            },
            {
                "mitigation": "Exploit Protection",
                "id": "M1050",
                "link": "https://attack.mitre.org/mitigations/M1050",
                "description": "Use capabilities to detect and block conditions that may lead to or be indicative of a software exploit occurring."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            }
        ]
    },
    {
        "technique": "Use Alternate Authentication Material",
        "id": "T1550",
        "link": "https://attack.mitre.org/techniques/T1550",
        "description": "Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls.",
        "sub-techniques": [
            {
                "sub-technique": "Application Access Token",
                "id": "T1550.001",
                "link": "https://attack.mitre.org/techniques/T1550/001",
                "description": "Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems. These tokens are typically stolen from users or services and used in lieu of login credentials."
            },
            {
                "sub-technique": "Pass the Ticket",
                "id": "T1550.003",
                "link": "https://attack.mitre.org/techniques/T1550/003",
                "description": "Adversaries may \"pass the ticket\" using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls. Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having access to an account's password. Kerberos authentication can be used as the first step to lateral movement to a remote system."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    }
]

collection = [
    {
        "technique": "Adversary-in-the-Middle",
        "id": "T1557",
        "link": "https://attack.mitre.org/techniques/T1557",
        "description": "Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation. By abusing features of common networking protocols that can determine the flow of network traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to communicate through an adversary controlled system so they can collect information or perform additional actions.",
        "sub-techniques": [
            {
                "sub-technique": "LLMNR/NBT-NS Poisoning and SMB Relay",
                "id": "T1557.001",
                "link": "https://attack.mitre.org/techniques/T1557/001",
                "description": "By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials."
            },
            {
                "sub-technique": "DHCP Spoofing",
                "id": "T1557.003",
                "link": "https://attack.mitre.org/techniques/T1557/003",
                "description": "Adversaries may redirect network traffic to adversary-owned systems by spoofing Dynamic Host Configuration Protocol (DHCP) traffic and acting as a malicious DHCP server on the victim network. By achieving the adversary-in-the-middle (AiTM) position, adversaries may collect network communications, including passed credentials, especially those sent over insecure, unencrypted protocols. This may also enable follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Encrypt Sensitive Information",
                "id": "M1041",
                "link": "https://attack.mitre.org/mitigations/M1041",
                "description": "Protect sensitive information with strong encryption."
            },
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            },
            {
                "mitigation": "Limit Access to Resource Over Network",
                "id": "M1035",
                "link": "https://attack.mitre.org/mitigations/M1035",
                "description": "Prevent access to file shares, remote access to systems, unnecessary services. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc."
            },
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    },
    {
        "technique": "Archive Collected Data",
        "id": "T1560",
        "link": "https://attack.mitre.org/techniques/T1560",
        "description": "An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network. Encryption can be used to hide information that is being exfiltrated from detection or make exfiltration less conspicuous upon inspection by a defender.",
        "sub-techniques": [
            {
                "sub-technique": "Archive via Utility",
                "id": "T1560.001",
                "link": "https://attack.mitre.org/techniques/T1560/001",
                "description": "Adversaries may use utilities to compress and/or encrypt collected data prior to exfiltration. Many utilities include functionalities to compress, encrypt, or otherwise package data into a format that is easier/more secure to transport."
            },
            {
                "sub-technique": "Archive via Custom Method",
                "id": "T1560.003",
                "link": "https://attack.mitre.org/techniques/T1560/003",
                "description": "An adversary may compress or encrypt data that is collected prior to exfiltration using a custom method. Adversaries may choose to use custom archival methods, such as encryption with XOR or stream ciphers implemented with no external library or utility references. Custom implementations of well-known compression algorithms have also been used."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            }
        ]
    },
    {
        "technique": "Audio Capture",
        "id": "T1123",
        "link": "https://attack.mitre.org/techniques/T1123",
        "description": "An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Automated Collection",
        "id": "T1119",
        "link": "https://attack.mitre.org/techniques/T1119",
        "description": "Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of a Command and Scripting Interpreter to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. In cloud-based environments, adversaries may also use cloud APIs, command line interfaces, or extract, transform, and load (ETL) services to automatically collect data. This functionality could also be built into remote access tools.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Encrypt Sensitive Information",
                "id": "M1041",
                "link": "https://attack.mitre.org/mitigations/M1041",
                "description": "Protect sensitive information with strong encryption."
            },
            {
                "mitigation": "Remote Data Storage",
                "id": "M1029",
                "link": "https://attack.mitre.org/mitigations/M1029",
                "description": "Use remote security log and sensitive file storage where access can be controlled better to prevent exposure of intrusion detection log data or sensitive information."
            }
        ]
    },
    {
        "technique": "Browser Session Hijacking",
        "id": "T1185",
        "link": "https://attack.mitre.org/techniques/T1185",
        "description": "Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify user-behaviors, and intercept information as part of various browser session hijacking techniques.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    },
    {
        "technique": "Clipboard Data",
        "id": "T1115",
        "link": "https://attack.mitre.org/techniques/T1115",
        "description": "Adversaries may collect data stored in the clipboard from users copying information within or between applications.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Data from Cloud Storage",
        "id": "T1530",
        "link": "https://attack.mitre.org/techniques/T1530",
        "description": "Adversaries may access data from improperly secured cloud storage.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Encrypt Sensitive Information",
                "id": "M1041",
                "link": "https://attack.mitre.org/mitigations/M1041",
                "description": "Protect sensitive information with strong encryption."
            },
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            },
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Data from Configuration Repository",
        "id": "T1602",
        "link": "https://attack.mitre.org/techniques/T1602",
        "description": "Adversaries may collect data related to managed devices from configuration repositories. Configuration repositories are used by management systems in order to configure, manage, and control data on remote systems. Configuration repositories may also facilitate remote access and administration of devices.",
        "sub-techniques": [
            {
                "sub-technique": "SNMP (MIB Dump)",
                "id": "T1602.001",
                "link": "https://attack.mitre.org/techniques/T1602/001",
                "description": "Adversaries may target the Management Information Base (MIB) to collect and/or mine valuable information in a network managed using Simple Network Management Protocol (SNMP)."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Encrypt Sensitive Information",
                "id": "M1041",
                "link": "https://attack.mitre.org/mitigations/M1041",
                "description": "Protect sensitive information with strong encryption."
            },
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            },
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            },
            {
                "mitigation": "Software Configuration",
                "id": "M1054",
                "link": "https://attack.mitre.org/mitigations/M1054",
                "description": "Implement configuration changes to software (other than the operating system) to mitigate security risks associated to how the software operates."
            },
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            }
        ]
    },
    {
        "technique": "Data from Information Repositories",
        "id": "T1213",
        "link": "https://attack.mitre.org/techniques/T1213",
        "description": "Adversaries may leverage information repositories to mine valuable information. Information repositories are tools that allow for storage of information, typically to facilitate collaboration or information sharing between users, and can store a wide variety of data that may aid adversaries in further objectives, or direct access to the target information. Adversaries may also abuse external sharing features to share sensitive documents with recipients outside of the organization.",
        "sub-techniques": [
            {
                "sub-technique": "Confluence",
                "id": "T1213.001",
                "link": "https://attack.mitre.org/techniques/T1213/001",
                "description": "Adversaries may leverage Confluence repositories to mine valuable information. Often found in development environments alongside Atlassian JIRA, Confluence is generally used to store development-related documentation, however, in general may contain more diverse categories of useful information, such as:"
            },
            {
                "sub-technique": "Code Repositories",
                "id": "T1213.003",
                "link": "https://attack.mitre.org/techniques/T1213/003",
                "description": "Adversaries may leverage code repositories to collect valuable information. Code repositories are tools/services that store source code and automate software builds. They may be hosted internally or privately on third party sites such as Github, GitLab, SourceForge, and BitBucket. Users typically interact with code repositories through a web application or command-line utilities such as git."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            },
            {
                "mitigation": "User Training",
                "id": "M1017",
                "link": "https://attack.mitre.org/mitigations/M1017",
                "description": "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
            }
        ]
    },
    {
        "technique": "Data from Local System",
        "id": "T1005",
        "link": "https://attack.mitre.org/techniques/T1005",
        "description": "Adversaries may search local system sources, such as file systems and configuration files or local databases, to find files of interest and sensitive data prior to Exfiltration.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Data Loss Prevention",
                "id": "M1057",
                "link": "https://attack.mitre.org/mitigations/M1057",
                "description": "Use a data loss prevention (DLP) strategy to categorize sensitive data, identify data formats indicative of personal identifiable information (PII), and restrict exfiltration of sensitive data.[1]"
            }
        ]
    },
    {
        "technique": "Data from Network Shared Drive",
        "id": "T1039",
        "link": "https://attack.mitre.org/techniques/T1039",
        "description": "Adversaries may search network shares on computers they have compromised to find files of interest. Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration. Interactive command shells may be in use, and common functionality within cmd may be used to gather information.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Data from Removable Media",
        "id": "T1025",
        "link": "https://attack.mitre.org/techniques/T1025",
        "description": "Adversaries may search connected removable media on computers they have compromised to find files of interest. Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to Exfiltration. Interactive command shells may be in use, and common functionality within cmd may be used to gather information.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Data Loss Prevention",
                "id": "M1057",
                "link": "https://attack.mitre.org/mitigations/M1057",
                "description": "Use a data loss prevention (DLP) strategy to categorize sensitive data, identify data formats indicative of personal identifiable information (PII), and restrict exfiltration of sensitive data.[1]"
            }
        ]
    },
    {
        "technique": "Data Staged",
        "id": "T1074",
        "link": "https://attack.mitre.org/techniques/T1074",
        "description": "Adversaries may stage collected data in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Archive Collected Data. Interactive command shells may be used, and common functionality within cmd and bash may be used to copy data into a staging location.",
        "sub-techniques": [
            {
                "sub-technique": "Local Data Staging",
                "id": "T1074.001",
                "link": "https://attack.mitre.org/techniques/T1074/001",
                "description": "Adversaries may stage collected data in a central location or directory on the local system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Archive Collected Data. Interactive command shells may be used, and common functionality within cmd and bash may be used to copy data into a staging location."
            }
        ],
        "mitigations": []
    },
    {
        "technique": "Email Collection",
        "id": "T1114",
        "link": "https://attack.mitre.org/techniques/T1114",
        "description": "Adversaries may target user email to collect sensitive information. Emails may contain sensitive data, including trade secrets or personal information, that can prove valuable to adversaries. Adversaries can collect or forward email from mail servers or clients.",
        "sub-techniques": [
            {
                "sub-technique": "Local Email Collection",
                "id": "T1114.001",
                "link": "https://attack.mitre.org/techniques/T1114/001",
                "description": "Adversaries may target user email on local systems to collect sensitive information. Files containing email data can be acquired from a user’s local system, such as Outlook storage or cache files."
            },
            {
                "sub-technique": "Email Forwarding Rule",
                "id": "T1114.003",
                "link": "https://attack.mitre.org/techniques/T1114/003",
                "description": "Adversaries may setup email forwarding rules to collect sensitive information. Adversaries may abuse email forwarding rules to monitor the activities of a victim, steal information, and further gain intelligence on the victim or the victim’s organization to use as part of further exploits or operations. Furthermore, email forwarding rules can allow adversaries to maintain persistent access to victim's emails even after compromised credentials are reset by administrators. Most email clients allow users to create inbox rules for various email functions, including forwarding to a different recipient. These rules may be created through a local email application, a web interface, or by command-line interface. Messages can be forwarded to internal or external recipients, and there are no restrictions limiting the extent of this rule. Administrators may also create forwarding rules for user accounts with the same considerations and outcomes."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Audit",
                "id": "M1047",
                "link": "https://attack.mitre.org/mitigations/M1047",
                "description": "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
            },
            {
                "mitigation": "Encrypt Sensitive Information",
                "id": "M1041",
                "link": "https://attack.mitre.org/mitigations/M1041",
                "description": "Protect sensitive information with strong encryption."
            },
            {
                "mitigation": "Multi-factor Authentication",
                "id": "M1032",
                "link": "https://attack.mitre.org/mitigations/M1032",
                "description": "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
            }
        ]
    },
    {
        "technique": "Input Capture",
        "id": "T1056",
        "link": "https://attack.mitre.org/techniques/T1056",
        "description": "Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. Credential API Hooking) or rely on deceiving the user into providing input into what they believe to be a genuine service (e.g. Web Portal Capture).",
        "sub-techniques": [
            {
                "sub-technique": "Keylogging",
                "id": "T1056.001",
                "link": "https://attack.mitre.org/techniques/T1056/001",
                "description": "Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when OS Credential Dumping efforts are not effective, and may require an adversary to intercept keystrokes on a system for a substantial period of time before credentials can be successfully captured."
            },
            {
                "sub-technique": "Web Portal Capture",
                "id": "T1056.003",
                "link": "https://attack.mitre.org/techniques/T1056/003",
                "description": "Adversaries may install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. For example, a compromised login page may log provided user credentials before logging the user in to the service."
            }
        ],
        "mitigations": []
    },
    {
        "technique": "Screen Capture",
        "id": "T1113",
        "link": "https://attack.mitre.org/techniques/T1113",
        "description": "Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. Taking a screenshot is also typically possible through native utilities or API calls, such as CopyFromScreen, xwd, or screencapture.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Video Capture",
        "id": "T1125",
        "link": "https://attack.mitre.org/techniques/T1125",
        "description": "An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information. Images may also be captured from devices or applications, potentially in specified intervals, in lieu of video files.",
        "sub-techniques": [],
        "mitigations": []
    }
]

command_and_control = [
    {
        "technique": "Application Layer Protocol",
        "id": "T1071",
        "link": "https://attack.mitre.org/techniques/T1071",
        "description": "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.",
        "sub-techniques": [
            {
                "sub-technique": "Web Protocols",
                "id": "T1071.001",
                "link": "https://attack.mitre.org/techniques/T1071/001",
                "description": "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server."
            },
            {
                "sub-technique": "Mail Protocols",
                "id": "T1071.003",
                "link": "https://attack.mitre.org/techniques/T1071/003",
                "description": "Adversaries may communicate using application layer protocols associated with electronic mail delivery to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            }
        ]
    },
    {
        "technique": "Communication Through Removable Media",
        "id": "T1092",
        "link": "https://attack.mitre.org/techniques/T1092",
        "description": "Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system. Both systems would need to be compromised, with the likelihood that an Internet-connected system was compromised first and the second through lateral movement by Replication Through Removable Media. Commands and files would be relayed from the disconnected system to the Internet-connected system to which the adversary has direct access.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            }
        ]
    },
    {
        "technique": "Data Encoding",
        "id": "T1132",
        "link": "https://attack.mitre.org/techniques/T1132",
        "description": "Adversaries may encode data to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system. Use of data encoding may adhere to existing protocol specifications and includes use of ASCII, Unicode, Base64, MIME, or other binary-to-text and character encoding systems.  Some data encoding systems may also result in data compression, such as gzip.",
        "sub-techniques": [
            {
                "sub-technique": "Standard Encoding",
                "id": "T1132.001",
                "link": "https://attack.mitre.org/techniques/T1132/001",
                "description": "Adversaries may encode data with a standard data encoding system to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system that adheres to existing protocol specifications. Common data encoding schemes include ASCII, Unicode, hexadecimal, Base64, and MIME. Some data encoding systems may also result in data compression, such as gzip."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            }
        ]
    },
    {
        "technique": "Data Obfuscation",
        "id": "T1001",
        "link": "https://attack.mitre.org/techniques/T1001",
        "description": "Adversaries may obfuscate command and control traffic to make it more difficult to detect. Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being seen. This encompasses many methods, such as adding junk data to protocol traffic, using steganography, or impersonating legitimate protocols.",
        "sub-techniques": [
            {
                "sub-technique": "Junk Data",
                "id": "T1001.001",
                "link": "https://attack.mitre.org/techniques/T1001/001",
                "description": "Adversaries may add junk data to protocols used for command and control to make detection more difficult. By adding random or meaningless data to the protocols used for command and control, adversaries can prevent trivial methods for decoding, deciphering, or otherwise analyzing the traffic. Examples may include appending/prepending data with junk characters or writing junk characters between significant characters."
            },
            {
                "sub-technique": "Protocol Impersonation",
                "id": "T1001.003",
                "link": "https://attack.mitre.org/techniques/T1001/003",
                "description": "Adversaries may impersonate legitimate protocols or web service traffic to disguise command and control activity and thwart analysis efforts. By impersonating legitimate protocols or web services, adversaries can make their command and control traffic blend in with legitimate network traffic."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            }
        ]
    },
    {
        "technique": "Dynamic Resolution",
        "id": "T1568",
        "link": "https://attack.mitre.org/techniques/T1568",
        "description": "Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations. This may be achieved by using malware that shares a common algorithm with the infrastructure the adversary uses to receive the malware's communications. These calculations can be used to dynamically adjust parameters such as the domain name, IP address, or port number the malware uses for command and control.",
        "sub-techniques": [
            {
                "sub-technique": "Fast Flux DNS",
                "id": "T1568.001",
                "link": "https://attack.mitre.org/techniques/T1568/001",
                "description": "Adversaries may use Fast Flux DNS to hide a command and control channel behind an array of rapidly changing IP addresses linked to a single domain resolution. This technique uses a fully qualified domain name, with multiple IP addresses assigned to it which are swapped with high frequency, using a combination of round robin IP addressing and short Time-To-Live (TTL) for a DNS resource record."
            },
            {
                "sub-technique": "DNS Calculation",
                "id": "T1568.003",
                "link": "https://attack.mitre.org/techniques/T1568/003",
                "description": "Adversaries may perform calculations on addresses returned in DNS results to determine which port and IP address to use for command and control, rather than relying on a predetermined port number or the actual returned IP address. A IP and/or port number calculation can be used to bypass egress filtering on a C2 channel."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            },
            {
                "mitigation": "Restrict Web-Based Content",
                "id": "M1021",
                "link": "https://attack.mitre.org/mitigations/M1021",
                "description": "Restrict use of certain websites, block downloads/attachments, block Javascript, restrict browser extensions, etc."
            }
        ]
    },
    {
        "technique": "Encrypted Channel",
        "id": "T1573",
        "link": "https://attack.mitre.org/techniques/T1573",
        "description": "Adversaries may employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if secret keys are encoded and/or generated within malware samples/configuration files.",
        "sub-techniques": [
            {
                "sub-technique": "Symmetric Cryptography",
                "id": "T1573.001",
                "link": "https://attack.mitre.org/techniques/T1573/001",
                "description": "Adversaries may employ a known symmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Symmetric encryption algorithms use the same key for plaintext encryption and ciphertext decryption. Common symmetric encryption algorithms include AES, DES, 3DES, Blowfish, and RC4."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            },
            {
                "mitigation": "SSL/TLS Inspection",
                "id": "M1020",
                "link": "https://attack.mitre.org/mitigations/M1020",
                "description": "Break and inspect SSL/TLS sessions to look at encrypted web traffic for adversary activity."
            }
        ]
    },
    {
        "technique": "Fallback Channels",
        "id": "T1008",
        "link": "https://attack.mitre.org/techniques/T1008",
        "description": "Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            }
        ]
    },
    {
        "technique": "Ingress Tool Transfer",
        "id": "T1105",
        "link": "https://attack.mitre.org/techniques/T1105",
        "description": "Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network through the command and control channel or through alternate protocols such as ftp. Once present, adversaries may also transfer/spread tools between victim devices within a compromised environment (i.e. Lateral Tool Transfer).",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            }
        ]
    },
    {
        "technique": "Multi-Stage Channels",
        "id": "T1104",
        "link": "https://attack.mitre.org/techniques/T1104",
        "description": "Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions. Use of multiple stages may obfuscate the command and control channel to make detection more difficult.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            }
        ]
    },
    {
        "technique": "Non-Application Layer Protocol",
        "id": "T1095",
        "link": "https://attack.mitre.org/techniques/T1095",
        "description": "Adversaries may use an OSI non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive. Specific examples include use of network layer protocols, such as the Internet Control Message Protocol (ICMP), transport layer protocols, such as the User Datagram Protocol (UDP), session layer protocols, such as Socket Secure (SOCKS), as well as redirected/tunneled protocols, such as Serial over LAN (SOL).",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            },
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            }
        ]
    },
    {
        "technique": "Non-Standard Port",
        "id": "T1571",
        "link": "https://attack.mitre.org/techniques/T1571",
        "description": "Adversaries may communicate using a protocol and port pairing that are typically not associated. For example, HTTPS over port 8088 or port 587 as opposed to the traditional port 443. Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            }
        ]
    },
    {
        "technique": "Protocol Tunneling",
        "id": "T1572",
        "link": "https://attack.mitre.org/techniques/T1572",
        "description": "Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems. Tunneling involves explicitly encapsulating a protocol within another. This behavior may conceal malicious traffic by blending in with existing traffic and/or provide an outer layer of encryption (similar to a VPN). Tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as SMB, RDP, or other traffic that would be filtered by network appliances or not routed over the Internet.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            },
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            }
        ]
    },
    {
        "technique": "Proxy",
        "id": "T1090",
        "link": "https://attack.mitre.org/techniques/T1090",
        "description": "Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap.  Adversaries use these types of proxies to manage command and control communications, reduce the number of simultaneous outbound network connections, provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between victims to avoid suspicion. Adversaries may chain together multiple proxies to further disguise the source of malicious traffic.",
        "sub-techniques": [
            {
                "sub-technique": "Internal Proxy",
                "id": "T1090.001",
                "link": "https://attack.mitre.org/techniques/T1090/001",
                "description": "Adversaries may use an internal proxy to direct command and control traffic between two or more systems in a compromised environment. Many tools exist that enable traffic redirection through proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap.  Adversaries use internal proxies to manage command and control communications inside a compromised environment, to reduce the number of simultaneous outbound network connections, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between infected systems to avoid suspicion. Internal proxy connections may use common peer-to-peer (p2p) networking protocols, such as SMB, to better blend in with the environment."
            },
            {
                "sub-technique": "Multi-hop Proxy",
                "id": "T1090.003",
                "link": "https://attack.mitre.org/techniques/T1090/003",
                "description": "To disguise the source of malicious traffic, adversaries may chain together multiple proxies. Typically, a defender will be able to identify the last proxy traffic traversed before it enters their network; the defender may or may not be able to identify any previous proxies before the last-hop proxy. This technique makes identifying the original source of the malicious traffic even more difficult by requiring the defender to trace malicious traffic through several proxies to identify its source. A particular variant of this behavior is to use onion routing networks, such as the publicly available TOR network."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            },
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            },
            {
                "mitigation": "SSL/TLS Inspection",
                "id": "M1020",
                "link": "https://attack.mitre.org/mitigations/M1020",
                "description": "Break and inspect SSL/TLS sessions to look at encrypted web traffic for adversary activity."
            }
        ]
    },
    {
        "technique": "Remote Access Software",
        "id": "T1219",
        "link": "https://attack.mitre.org/techniques/T1219",
        "description": "An adversary may use legitimate desktop support and remote access software, such as Team Viewer, AnyDesk, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks. These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment. Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Execution Prevention",
                "id": "M1038",
                "link": "https://attack.mitre.org/mitigations/M1038",
                "description": "Block execution of code on a system through application control, and/or script blocking."
            },
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            },
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            }
        ]
    },
    {
        "technique": "Traffic Signaling",
        "id": "T1205",
        "link": "https://attack.mitre.org/techniques/T1205",
        "description": "Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control. Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port or executing a malicious task. This may take the form of sending a series of packets with certain characteristics before a port will be opened that the adversary can use for command and control. Usually this series of packets consists of attempted connections to a predefined sequence of closed ports (i.e. Port Knocking), but can involve unusual flags, specific strings, or other unique characteristics. After the sequence is completed, opening a port may be accomplished by the host-based firewall, but could also be implemented by custom software.",
        "sub-techniques": [
            {
                "sub-technique": "Port Knocking",
                "id": "T1205.001",
                "link": "https://attack.mitre.org/techniques/T1205/001",
                "description": "Adversaries may use port knocking to hide open ports used for persistence or command and control. To enable a port, an adversary sends a series of attempted connections to a predefined sequence of closed ports. After the sequence is completed, opening a port is often accomplished by the host based firewall, but could also be implemented by custom software."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            }
        ]
    },
    {
        "technique": "Web Service",
        "id": "T1102",
        "link": "https://attack.mitre.org/techniques/T1102",
        "description": "Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised system. Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.",
        "sub-techniques": [
            {
                "sub-technique": "Dead Drop Resolver",
                "id": "T1102.001",
                "link": "https://attack.mitre.org/techniques/T1102/001",
                "description": "Adversaries may use an existing, legitimate external Web service to host information that points to additional command and control (C2) infrastructure. Adversaries may post content, known as a dead drop resolver, on Web services with embedded (and often obfuscated/encoded) domains or IP addresses. Once infected, victims will reach out to and be redirected by these resolvers."
            },
            {
                "sub-technique": "One-Way Communication",
                "id": "T1102.003",
                "link": "https://attack.mitre.org/techniques/T1102/003",
                "description": "Adversaries may use an existing, legitimate external Web service as a means for sending commands to a compromised system without receiving return output over the Web service channel. Compromised systems may leverage popular websites and social media to host command and control (C2) instructions. Those infected systems may opt to send the output from those commands back over a different C2 channel, including to another distinct Web service. Alternatively, compromised systems may return no output at all in cases where adversaries want to send instructions to systems and do not want a response."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            },
            {
                "mitigation": "Restrict Web-Based Content",
                "id": "M1021",
                "link": "https://attack.mitre.org/mitigations/M1021",
                "description": "Restrict use of certain websites, block downloads/attachments, block Javascript, restrict browser extensions, etc."
            }
        ]
    }
]

exfiltration = [
    {
        "technique": "Automated Exfiltration",
        "id": "T1020",
        "link": "https://attack.mitre.org/techniques/T1020",
        "description": "Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection.",
        "sub-techniques": [
            {
                "sub-technique": "Traffic Duplication",
                "id": "T1020.001",
                "link": "https://attack.mitre.org/techniques/T1020/001",
                "description": "Adversaries may leverage traffic mirroring in order to automate data exfiltration over compromised infrastructure. Traffic mirroring is a native feature for some devices, often used for network analysis. For example, devices may be configured to forward network traffic to one or more destinations for analysis by a network analyzer or other monitoring device."
            }
        ],
        "mitigations": []
    },
    {
        "technique": "Data Transfer Size Limits",
        "id": "T1030",
        "link": "https://attack.mitre.org/techniques/T1030",
        "description": "An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            }
        ]
    },
    {
        "technique": "Exfiltration Over Alternative Protocol",
        "id": "T1048",
        "link": "https://attack.mitre.org/techniques/T1048",
        "description": "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.",
        "sub-techniques": [
            {
                "sub-technique": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
                "id": "T1048.001",
                "link": "https://attack.mitre.org/techniques/T1048/001",
                "description": "Adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server."
            },
            {
                "sub-technique": "Exfiltration Over Unencrypted Non-C2 Protocol",
                "id": "T1048.003",
                "link": "https://attack.mitre.org/techniques/T1048/003",
                "description": "Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Data Loss Prevention",
                "id": "M1057",
                "link": "https://attack.mitre.org/mitigations/M1057",
                "description": "Use a data loss prevention (DLP) strategy to categorize sensitive data, identify data formats indicative of personal identifiable information (PII), and restrict exfiltration of sensitive data.[1]"
            },
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            },
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Exfiltration Over C2 Channel",
        "id": "T1041",
        "link": "https://attack.mitre.org/techniques/T1041",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Data Loss Prevention",
                "id": "M1057",
                "link": "https://attack.mitre.org/mitigations/M1057",
                "description": "Use a data loss prevention (DLP) strategy to categorize sensitive data, identify data formats indicative of personal identifiable information (PII), and restrict exfiltration of sensitive data.[1]"
            },
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            }
        ]
    },
    {
        "technique": "Exfiltration Over Other Network Medium",
        "id": "T1011",
        "link": "https://attack.mitre.org/techniques/T1011",
        "description": "Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel. If the command and control network is a wired Internet connection, the exfiltration may occur, for example, over a WiFi connection, modem, cellular data connection, Bluetooth, or another radio frequency (RF) channel.",
        "sub-techniques": [
            {
                "sub-technique": "Exfiltration Over Bluetooth",
                "id": "T1011.001",
                "link": "https://attack.mitre.org/techniques/T1011/001",
                "description": "Adversaries may attempt to exfiltrate data over Bluetooth rather than the command and control channel. If the command and control network is a wired Internet connection, an adversary may opt to exfiltrate data using a Bluetooth communication channel."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            }
        ]
    },
    {
        "technique": "Exfiltration Over Physical Medium",
        "id": "T1052",
        "link": "https://attack.mitre.org/techniques/T1052",
        "description": "Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user. Such media could be an external hard drive, USB drive, cellular phone, MP3 player, or other removable storage and processing device. The physical medium or device could be used as the final exfiltration point or to hop between otherwise disconnected systems.",
        "sub-techniques": [
            {
                "sub-technique": "Exfiltration over USB",
                "id": "T1052.001",
                "link": "https://attack.mitre.org/techniques/T1052/001",
                "description": "Adversaries may attempt to exfiltrate data over a USB connected physical device. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a USB device introduced by a user. The USB device could be used as the final exfiltration point or to hop between otherwise disconnected systems."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Data Loss Prevention",
                "id": "M1057",
                "link": "https://attack.mitre.org/mitigations/M1057",
                "description": "Use a data loss prevention (DLP) strategy to categorize sensitive data, identify data formats indicative of personal identifiable information (PII), and restrict exfiltration of sensitive data.[1]"
            },
            {
                "mitigation": "Disable or Remove Feature or Program",
                "id": "M1042",
                "link": "https://attack.mitre.org/mitigations/M1042",
                "description": "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
            },
            {
                "mitigation": "Limit Hardware Installation",
                "id": "M1034",
                "link": "https://attack.mitre.org/mitigations/M1034",
                "description": "Block users or groups from installing or using unapproved hardware on systems, including USB devices."
            }
        ]
    },
    {
        "technique": "Exfiltration Over Web Service",
        "id": "T1567",
        "link": "https://attack.mitre.org/techniques/T1567",
        "description": "Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. Popular Web services acting as an exfiltration mechanism may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to compromise. Firewall rules may also already exist to permit traffic to these services.",
        "sub-techniques": [
            {
                "sub-technique": "Exfiltration to Code Repository",
                "id": "T1567.001",
                "link": "https://attack.mitre.org/techniques/T1567/001",
                "description": "Adversaries may exfiltrate data to a code repository rather than over their primary command and control channel. Code repositories are often accessible via an API (ex: https://api.github.com). Access to these APIs are often over HTTPS, which gives the adversary an additional level of protection."
            },
            {
                "sub-technique": "Exfiltration to Text Storage Sites",
                "id": "T1567.003",
                "link": "https://attack.mitre.org/techniques/T1567/003",
                "description": "Adversaries may exfiltrate data to text storage sites instead of their primary command and control channel. Text storage sites, such as pastebin[.]com, are commonly used by developers to share code and other information."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Data Loss Prevention",
                "id": "M1057",
                "link": "https://attack.mitre.org/mitigations/M1057",
                "description": "Use a data loss prevention (DLP) strategy to categorize sensitive data, identify data formats indicative of personal identifiable information (PII), and restrict exfiltration of sensitive data.[1]"
            },
            {
                "mitigation": "Restrict Web-Based Content",
                "id": "M1021",
                "link": "https://attack.mitre.org/mitigations/M1021",
                "description": "Restrict use of certain websites, block downloads/attachments, block Javascript, restrict browser extensions, etc."
            }
        ]
    },
    {
        "technique": "Scheduled Transfer",
        "id": "T1029",
        "link": "https://attack.mitre.org/techniques/T1029",
        "description": "Adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals. This could be done to blend traffic patterns with normal activity or availability.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Network Intrusion Prevention",
                "id": "M1031",
                "link": "https://attack.mitre.org/mitigations/M1031",
                "description": "Use intrusion detection signatures to block traffic at network boundaries."
            }
        ]
    },
    {
        "technique": "Transfer Data to Cloud Account",
        "id": "T1537",
        "link": "https://attack.mitre.org/techniques/T1537",
        "description": "Adversaries may exfiltrate data by transferring the data, including backups of cloud environments, to another cloud account they control on the same service to avoid typical file transfers/downloads and network-based exfiltration detection.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            },
            {
                "mitigation": "Password Policies",
                "id": "M1027",
                "link": "https://attack.mitre.org/mitigations/M1027",
                "description": "Set and enforce secure password policies for accounts."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    }
]

impact = [
    {
        "technique": "Account Access Removal",
        "id": "T1531",
        "link": "https://attack.mitre.org/techniques/T1531",
        "description": "Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials) to remove access to accounts. Adversaries may also subsequently log off and/or perform a System Shutdown/Reboot to set malicious changes into place.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Data Destruction",
        "id": "T1485",
        "link": "https://attack.mitre.org/techniques/T1485",
        "description": "Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources. Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives. Common operating system file deletion commands such as del and rm often only remove pointers to files without wiping the contents of the files themselves, making the files recoverable by proper forensic methodology. This behavior is distinct from Disk Content Wipe and Disk Structure Wipe because individual files are destroyed rather than sections of a storage disk or the disk's logical structure.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Data Backup",
                "id": "M1053",
                "link": "https://attack.mitre.org/mitigations/M1053",
                "description": "Take and store data backups from end user systems and critical servers. Ensure backup and storage systems are hardened and kept separate from the corporate network to prevent compromise."
            }
        ]
    },
    {
        "technique": "Data Encrypted for Impact",
        "id": "T1486",
        "link": "https://attack.mitre.org/techniques/T1486",
        "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives and withholding access to a decryption key. This may be done in order to extract monetary compensation from a victim in exchange for decryption or a decryption key (ransomware) or to render data permanently inaccessible in cases where the key is not saved or transmitted.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Behavior Prevention on Endpoint",
                "id": "M1040",
                "link": "https://attack.mitre.org/mitigations/M1040",
                "description": "Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
            },
            {
                "mitigation": "Data Backup",
                "id": "M1053",
                "link": "https://attack.mitre.org/mitigations/M1053",
                "description": "Take and store data backups from end user systems and critical servers. Ensure backup and storage systems are hardened and kept separate from the corporate network to prevent compromise."
            }
        ]
    },
    {
        "technique": "Data Manipulation",
        "id": "T1565",
        "link": "https://attack.mitre.org/techniques/T1565",
        "description": "Adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity, thus threatening the integrity of the data. By manipulating data, adversaries may attempt to affect a business process, organizational understanding, or decision making.",
        "sub-techniques": [
            {
                "sub-technique": "Stored Data Manipulation",
                "id": "T1565.001",
                "link": "https://attack.mitre.org/techniques/T1565/001",
                "description": "Adversaries may insert, delete, or manipulate data at rest in order to influence external outcomes or hide activity, thus threatening the integrity of the data. By manipulating stored data, adversaries may attempt to affect a business process, organizational understanding, and decision making."
            },
            {
                "sub-technique": "Runtime Data Manipulation",
                "id": "T1565.003",
                "link": "https://attack.mitre.org/techniques/T1565/003",
                "description": "Adversaries may modify systems in order to manipulate the data as it is accessed and displayed to an end user, thus threatening the integrity of the data. By manipulating runtime data, adversaries may attempt to affect a business process, organizational understanding, and decision making."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Encrypt Sensitive Information",
                "id": "M1041",
                "link": "https://attack.mitre.org/mitigations/M1041",
                "description": "Protect sensitive information with strong encryption."
            },
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            },
            {
                "mitigation": "Remote Data Storage",
                "id": "M1029",
                "link": "https://attack.mitre.org/mitigations/M1029",
                "description": "Use remote security log and sensitive file storage where access can be controlled better to prevent exposure of intrusion detection log data or sensitive information."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            }
        ]
    },
    {
        "technique": "Defacement",
        "id": "T1491",
        "link": "https://attack.mitre.org/techniques/T1491",
        "description": "Adversaries may modify visual content available internally or externally to an enterprise network, thus affecting the integrity of the original content. Reasons for Defacement include delivering messaging, intimidation, or claiming (possibly false) credit for an intrusion. Disturbing or offensive images may be used as a part of Defacement in order to cause user discomfort, or to pressure compliance with accompanying messages.",
        "sub-techniques": [
            {
                "sub-technique": "Internal Defacement",
                "id": "T1491.001",
                "link": "https://attack.mitre.org/techniques/T1491/001",
                "description": "An adversary may deface systems internal to an organization in an attempt to intimidate or mislead users, thus discrediting the integrity of the systems. This may take the form of modifications to internal websites, or directly to user systems with the replacement of the desktop wallpaper. Disturbing or offensive images may be used as a part of Internal Defacement in order to cause user discomfort, or to pressure compliance with accompanying messages. Since internally defacing systems exposes an adversary's presence, it often takes place after other intrusion goals have been accomplished."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Data Backup",
                "id": "M1053",
                "link": "https://attack.mitre.org/mitigations/M1053",
                "description": "Take and store data backups from end user systems and critical servers. Ensure backup and storage systems are hardened and kept separate from the corporate network to prevent compromise."
            }
        ]
    },
    {
        "technique": "Disk Wipe",
        "id": "T1561",
        "link": "https://attack.mitre.org/techniques/T1561",
        "description": "Adversaries may wipe or corrupt raw disk data on specific systems or in large numbers in a network to interrupt availability to system and network resources. With direct write access to a disk, adversaries may attempt to overwrite portions of disk data. Adversaries may opt to wipe arbitrary portions of disk data and/or wipe disk structures like the master boot record (MBR). A complete wipe of all disk sectors may be attempted.",
        "sub-techniques": [
            {
                "sub-technique": "Disk Content Wipe",
                "id": "T1561.001",
                "link": "https://attack.mitre.org/techniques/T1561/001",
                "description": "Adversaries may erase the contents of storage devices on specific systems or in large numbers in a network to interrupt availability to system and network resources."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Data Backup",
                "id": "M1053",
                "link": "https://attack.mitre.org/mitigations/M1053",
                "description": "Take and store data backups from end user systems and critical servers. Ensure backup and storage systems are hardened and kept separate from the corporate network to prevent compromise."
            }
        ]
    },
    {
        "technique": "Endpoint Denial of Service",
        "id": "T1499",
        "link": "https://attack.mitre.org/techniques/T1499",
        "description": "Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users. Endpoint DoS can be performed by exhausting the system resources those services are hosted on or exploiting the system to cause a persistent crash condition. Example services include websites, email services, DNS, and web-based applications. Adversaries have been observed conducting DoS attacks for political purposes and to support other malicious activities, including distraction, hacktivism, and extortion.",
        "sub-techniques": [
            {
                "sub-technique": "OS Exhaustion Flood",
                "id": "T1499.001",
                "link": "https://attack.mitre.org/techniques/T1499/001",
                "description": "Adversaries may launch a denial of service (DoS) attack targeting an endpoint's operating system (OS). A system's OS is responsible for managing the finite resources as well as preventing the entire system from being overwhelmed by excessive demands on its capacity. These attacks do not need to exhaust the actual resources on a system; the attacks may simply exhaust the limits and available resources that an OS self-imposes."
            },
            {
                "sub-technique": "Application Exhaustion Flood",
                "id": "T1499.003",
                "link": "https://attack.mitre.org/techniques/T1499/003",
                "description": "Adversaries may target resource intensive features of applications to cause a denial of service (DoS), denying availability to those applications. For example, specific features in web applications may be highly resource intensive. Repeated requests to those features may be able to exhaust system resources and deny access to the application or the server itself."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            }
        ]
    },
    {
        "technique": "Firmware Corruption",
        "id": "T1495",
        "link": "https://attack.mitre.org/techniques/T1495",
        "description": "Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other firmware in devices attached to a system in order to render them inoperable or unable to boot, thus denying the availability to use the devices and/or the system. Firmware is software that is loaded and executed from non-volatile memory on hardware devices in order to initialize and manage device functionality. These devices may include the motherboard, hard drive, or video cards.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Boot Integrity",
                "id": "M1046",
                "link": "https://attack.mitre.org/mitigations/M1046",
                "description": "Use secure methods to boot a system and verify the integrity of the operating system and loading mechanisms."
            },
            {
                "mitigation": "Privileged Account Management",
                "id": "M1026",
                "link": "https://attack.mitre.org/mitigations/M1026",
                "description": "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
            },
            {
                "mitigation": "Update Software",
                "id": "M1051",
                "link": "https://attack.mitre.org/mitigations/M1051",
                "description": "Perform regular software updates to mitigate exploitation risk."
            }
        ]
    },
    {
        "technique": "Inhibit System Recovery",
        "id": "T1490",
        "link": "https://attack.mitre.org/techniques/T1490",
        "description": "Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery. This may deny access to available backups and recovery options.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Data Backup",
                "id": "M1053",
                "link": "https://attack.mitre.org/mitigations/M1053",
                "description": "Take and store data backups from end user systems and critical servers. Ensure backup and storage systems are hardened and kept separate from the corporate network to prevent compromise."
            },
            {
                "mitigation": "Operating System Configuration",
                "id": "M1028",
                "link": "https://attack.mitre.org/mitigations/M1028",
                "description": "Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "Network Denial of Service",
        "id": "T1498",
        "link": "https://attack.mitre.org/techniques/T1498",
        "description": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Network DoS can be performed by exhausting the network bandwidth services rely on. Example resources include specific websites, email services, DNS, and web-based applications. Adversaries have been observed conducting network DoS attacks for political purposes and to support other malicious activities, including distraction, hacktivism, and extortion.",
        "sub-techniques": [
            {
                "sub-technique": "Direct Network Flood",
                "id": "T1498.001",
                "link": "https://attack.mitre.org/techniques/T1498/001",
                "description": "Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target. This DoS attack may also reduce the availability and functionality of the targeted system(s) and network. Direct Network Floods are when one or more systems are used to send a high-volume of network packets towards the targeted service's network. Almost any network protocol may be used for flooding. Stateless protocols such as UDP or ICMP are commonly used but stateful protocols such as TCP can be used as well."
            }
        ],
        "mitigations": [
            {
                "mitigation": "Filter Network Traffic",
                "id": "M1037",
                "link": "https://attack.mitre.org/mitigations/M1037",
                "description": "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
            }
        ]
    },
    {
        "technique": "Resource Hijacking",
        "id": "T1496",
        "link": "https://attack.mitre.org/techniques/T1496",
        "description": "Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems, which may impact system and/or hosted service availability.",
        "sub-techniques": [],
        "mitigations": []
    },
    {
        "technique": "Service Stop",
        "id": "T1489",
        "link": "https://attack.mitre.org/techniques/T1489",
        "description": "Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services or processes can inhibit or stop response to an incident or aid in the adversary's overall objectives to cause damage to the environment.",
        "sub-techniques": [],
        "mitigations": [
            {
                "mitigation": "Network Segmentation",
                "id": "M1030",
                "link": "https://attack.mitre.org/mitigations/M1030",
                "description": "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
            },
            {
                "mitigation": "Restrict File and Directory Permissions",
                "id": "M1022",
                "link": "https://attack.mitre.org/mitigations/M1022",
                "description": "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
            },
            {
                "mitigation": "Restrict Registry Permissions",
                "id": "M1024",
                "link": "https://attack.mitre.org/mitigations/M1024",
                "description": "Restrict the ability to modify certain hives or keys in the Windows Registry."
            },
            {
                "mitigation": "User Account Management",
                "id": "M1018",
                "link": "https://attack.mitre.org/mitigations/M1018",
                "description": "Manage the creation, modification, use, and permissions associated to user accounts."
            }
        ]
    },
    {
        "technique": "System Shutdown/Reboot",
        "id": "T1529",
        "link": "https://attack.mitre.org/techniques/T1529",
        "description": "Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems. Operating systems may contain commands to initiate a shutdown/reboot of a machine or network device. In some cases, these commands may also be used to initiate a shutdown/reboot of a remote computer or network device via Network Device CLI (e.g. reload).",
        "sub-techniques": [],
        "mitigations": []
    }
]

