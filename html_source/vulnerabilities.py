html_panel_vulns = """
<div>
    <h1 style="color:#bd93f9">%s</h1><br /> <!-- the name of the vuln -->
    <img src="%s" width="100" /> <!-- the base 64 image of the vulnerability -->
    <table>
        <tr>
            <th>MITRE ATT&CK ID: </th>
            <th style="color: #f96769">%s</th> <!-- the mitre attack id -->
        </tr>
    </table>
    <h3 style="color:#71e0cb">Description:</h3>
    <p>%s</p> <!-- the description of the vulnerability -->
    <h3 style="color:#71e0cb">Sample command:</h3>
    <div style="background-color:#3b3e50; padding: 5px 5px 5px 5px;">
        <p>%s</p> <!-- the sample command -->
    </div>
    <h3 style="color:#71e0cb">Resources:</h3>
    <ul> <!-- the different external resources -->
        %s
    </ul>
</div>
"""
