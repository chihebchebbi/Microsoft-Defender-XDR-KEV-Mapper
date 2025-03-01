import json
import termcolor # pip3 install termcolor
import pandas as pd # pip3 install pandas
import requests
import toml


# Banner 

banne = """
▗▖ ▗▖▗▄▄▄▖▗▖  ▗▖    ▗▖  ▗▖ ▗▄▖ ▗▄▄▖ ▗▄▄▖ ▗▄▄▄▖▗▄▄▖             
▐▌▗▞▘▐▌   ▐▌  ▐▌    ▐▛▚▞▜▌▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌▐▌   ▐▌ ▐▌            
▐▛▚▖ ▐▛▀▀▘▐▌  ▐▌    ▐▌  ▐▌▐▛▀▜▌▐▛▀▘ ▐▛▀▘ ▐▛▀▀▘▐▛▀▚▖            
▐▌ ▐▌▐▙▄▄▖ ▝▚▞▘     ▐▌  ▐▌▐▌ ▐▌▐▌   ▐▌   ▐▙▄▄▖▐▌ ▐▌ 
        Microsoft Defender XDR KEV Mapper                             
"""

print(termcolor.colored(banne, "cyan"))

# Load the configuration file
config = toml.load("Config/config.toml")
EntraID_Tenant = config["EntraID_Tenant"]
EntraID_ClientID = config["EntraID_ClientID"]
EntraID_ClientSecret = config["EntraID_ClientSecret"]

print(termcolor.colored("[+] Configuration File Loaded Successfully", "green"))

Access_Url = "https://login.microsoftonline.com/"+EntraID_Tenant+"/oauth2/token"
headers = {'Content-Type': 'application/x-www-form-urlencoded', 'scope': 'https://graph.microsoft.com/.default'}
payload='grant_type=client_credentials&client_id='+ EntraID_ClientID+'&resource=https://graph.microsoft.com&client_secret='+EntraID_ClientSecret
Access_response = requests.post(Access_Url, headers=headers, data=payload).json()
EntraID_Access_Token = Access_response["access_token"]
#print(EntraID_Access_Token)

print(termcolor.colored("[+] Access Token Obtained Successfully", "green"))

headersAD = {
    'Authorization': 'Bearer '+EntraID_Access_Token,
    'Content-Type': 'application/json'
}

# HuntingQuery URL to get the Defender Categories 
DefenderHuntingQueries_Url = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"

# Query to get the Defender Categories
payload = {
    "Query": """
let KnowExploitesVulnsCISA = externaldata(cveID: string, vendorProject: string, product: string, vulnerabilityName: string, dateAdded: datetime, shortDescription: string, requiredAction: string, dueDate: datetime, notes: string)[@"https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"] with (format="csv", ignoreFirstRecord=True);
DeviceTvmSoftwareVulnerabilities
| join kind=inner (KnowExploitesVulnsCISA) 
    on $left.CveId == $right.cveID
| project-reorder DeviceName, CveId, vendorProject, vulnerabilityName, dateAdded, shortDescription
| join kind=inner (DeviceTvmSoftwareVulnerabilities
    | summarize count() by tostring(CveId))
    on $left.CveId == $right.CveId
| summarize count() by CveId
| project CveId
"""
}

KEV_response = requests.post(DefenderHuntingQueries_Url, headers=headersAD, json=payload).json()
#print(KEV_response)

print(termcolor.colored("[+] Microsoft Defender Known Exploitable CVE Data Obtained Successfully", "green"))

CVEList = []

for CVE in KEV_response['results']:
    CVEList.append(CVE['CveId'])

#print(CVEList)

for CVE_ID in CVEList:

    # Load the dataset
    url = "https://center-for-threat-informed-defense.github.io/mappings-explorer/data/kev/attack-15.1/kev-02.13.2025/enterprise/kev-02.13.2025_attack-15.1-enterprise.csv"
    df = pd.read_csv(url)
    filtered_data = df[df['capability_id'] == CVE_ID]
    CfIDCVEIds = filtered_data['capability_id'].tolist()
    if CVE_ID in CfIDCVEIds:

        nodes = [{'data': {'id': CVE_ID, 'label': CVE_ID}}]
        edges = []
        # Define node categories
        exploitation_techniques = filtered_data[filtered_data['mapping_type'] == 'exploitation_technique']['attack_object_id'].tolist()
        primary_impacts = filtered_data[filtered_data['mapping_type'] == 'primary_impact']['attack_object_id'].tolist()
        secondary_impacts = filtered_data[filtered_data['mapping_type'] == 'secondary_impact']['attack_object_id'].tolist()

        # Generate nodes and edges
        all_categories = {
            'exploitation_technique': (exploitation_techniques, 'Allows'),
            'primary_impact': (primary_impacts, 'Enables'),
            'secondary_impact': (secondary_impacts, 'Leads to')
        }

        # Create nodes and edges
        for category, (items, label) in all_categories.items():
            for item in items:
                nodes.append({'data': {'id': item, 'label': item}})
                if category == 'exploitation_technique':
                    edges.append({'data': {'source': CVE_ID, 'target': item, 'label': label}})
                if category == 'primary_impact':
                    for et in exploitation_techniques:
                        edges.append({'data': {'source': et, 'target': item, 'label': label}})
                if category == 'secondary_impact':
                    for pi in primary_impacts:
                        edges.append({'data': {'source': pi, 'target': item, 'label': label}})

        # Convert nodes and edges to JSON for embedding in HTML
        nodes_json = json.dumps(nodes)
        edges_json = json.dumps(edges)

        # Generate the HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Graph Visualization</title>
            <script src="https://cdn.jsdelivr.net/npm/cytoscape@3.19.1/dist/cytoscape.min.js"></script>
            <script src="https://unpkg.com/dagre@0.7.4/dist/dagre.js"></script>
            <script src="https://cdn.rawgit.com/cytoscape/cytoscape.js-dagre/1.5.0/cytoscape-dagre.js"></script>
            <style>
                #cy {{
                    width: 100%;
                    height: 80vh;
                    position: relative;

                }}
            </style>
        </head>
        <body>
            <div id="cy"></div>
            <script>
                var cy = cytoscape({{
                    container: document.getElementById('cy'),
                    elements: {{
                        nodes: {nodes_json},
                        edges: {edges_json}
                    }},
                    style: [
                        {{
                            selector: 'node',
                            style: {{
                                'background-color': 'white',
                                'label': 'data(label)',
                                'background-image': function(ele) {{
                                    return ele.data('label').includes('CVE') ? 
                                        'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSud2AgebbuyeaqAbnkPjZhNeQnWgp7dWdtAp2bLL0qDIllP211A6LiUJdwZNM07Xesd8w&usqp=CAU' : 
                                        'https://cdn-icons-png.flaticon.com/512/6019/6019117.png';
                                }},
                                'background-fit': 'cover',
                            }}
                        }},
                        {{
                            selector: 'edge',
                            style: {{
                                'width': 3,
                                'line-color': '#ccc',
                                'target-arrow-color': '#ccc',
                                'target-arrow-shape': 'triangle',
                                'curve-style': 'bezier',
                                'label': 'data(label)',
                                'text-rotation': 'autorotate'
                            }}
                        }}
                    ],
                    layout: {{
                        name: 'dagre',
                        directed: false,
                        rankDir: 'LR',
                        padding: 20,
                        spacingFactor: 1.2,
                        avoidOverlap: true,
                    }}
                }});
            </script>
        </body>
        </html>
        """

        # Write the HTML content to a file
        FileName = "Reports/"+str(CVE_ID) + ".html"
        with open(FileName, "w") as file:
            file.write(html_content)

        print("[+] "+FileName+" HTML file generated successfully!")
    else:
        print(termcolor.colored("[!] CVE ID "+CVE_ID+" not found in the dataset", "red"))

print(termcolor.colored("[+] HTML Files Generated Successfully", "green"))