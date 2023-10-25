# havoc-reporter

A havoc UI python module to help in reporting any vulnerabilities to exploit on
an internal network. This module covers general network vulnerabilities, active
directory exploit techniques and Windows privilege escalation. It uses a tree
interface to list out the vulnerabilities and a HTML web text browser to display
the vulnerability and it's information. The HTML page can be edited to fit the
style of any reports since the web view allows for styled text copying and can
be pasted directly inside of a report.

![Screenshot of Tree Window]()

## Install:

Currently this plugin only works on the dev branch on [Havoc](https://github.com/HavocFramework/Havoc/tree/dev).
You will need to compile the client on your own to then use this module. It is
first recommended to clone this repository using the following command:
```
 $ git clone https://github.com/p4p1/havoc-reporter
```
To import the module launch the client and navigate to *Scripts Manager* then
*Load Script* like shown in the following screenshots.

![Script Manager]()
![Load Script]()

You will need to import the reporter.py python script since that is the main
script.

![Import Script]()

## Customization:

### HTML style:

Currently this plugin save it's HTML inside of the reporter.py script directly
in the source. You will find in the code the *html_panel_vulns* variable which
has the HTML for the vulnerabilities. This can then be modified to fit your
reporting theme.

![HTML code]()

### Adding vulnerabilities:

To add new vulnerabilities to this script you will need to follow the following
dictionary structure:
```
    {
        "title": "Title of the vulnerability",
        "desc": "Description of the vulnerabiltity",
        "image": "data:image/png;base64,base_64_data_of_image==",
        "mitre": "T1038", # The MITRE ATT&CK number if applicable
        "external": [
            {
                "title": "Title of the external resource",
                "link": "http://link_to_external_resource"
            }
        ],
        "command": "$ The comand to be ran to test the vulnerability"
    }
```
These dictionary elements can then be added to their respective categories
currently we have the three following categories:
 - General network vulnerabilities (network_vulnerabilities.py)
 - Active Directory vulnerabilities (active_directory.py)
 - Windows privilege escalation vulnerabilities (windows_privesc.py)

## Support:

If you like this small plugin and want to support by adding more vulnerabilities
you are invited to do so by cloning the repository and adding more. I also need
help in generating base64 images that represent the vulnerabilities that are in
place.
