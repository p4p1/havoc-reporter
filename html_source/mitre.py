html_panel_mitre = """
<div>
    <h1 style="color:#bd93f9">%s</h1><br /><!-- title of the mitre attack -->
    <img src="%s" width="100" /> <!-- base 64 of the image representing the categorie -->
    <table>
        <tr>
            <th>MITRE ATT&CK ID: </th>
            <th style="color: #f96769">%s</th> <!-- the attack id -->
        </tr>
    </table>
    <h3 style="color:#71e0cb">Description:</h3>
    <p>%s</p><!-- the descirpiton of the attack -->
    %s <!-- the sub techniques -->
    %s <!-- The  mitigations of the attack -->
</div>
"""
