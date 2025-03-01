# Microsoft Defender XDR and CISA KEV Mapping Tool

## Overview

This tool is designed to enhance cybersecurity measures by automatically checking vulnerabilities detected by Microsoft Defender for Endpoint against the Cybersecurity and Infrastructure Security Agency’s (CISA) Known Exploitable Vulnerabilities (KEV) catalog. Upon identifying a match, the tool leverages the comprehensive mapping system provided by the Center for Threat-Informed Defense to visually represent relationships and implications of these vulnerabilities through detailed graph visualizations.

Please Note: While this tool utilizes mapping data from the Center for Threat-Informed Defense, the Center is not implicated in the development of this tool or responsible for its functionality.

![](https://i.imgur.com/MpiD3zW.png)

## Key Features

* Data Collection: The tool interfaces with Microsoft Defender to retrieve current vulnerability data from endpoints.
* Vulnerability Matching: Utilizes a regularly updated database of CISA’s KEV to identify overlaps with detected vulnerabilities.
* Graph Generation: For each matched CVE, the tool generates a visual graph that maps out the exploitation techniques and potential impacts as defined by the Threat-Informed Defense mappings.
* Reporting: Outputs are provided as interactive HTML graph visualizations that can be used for presentations, reports, and strategic planning.

## Usage
```bash
# Clone the repository
git clone https://github.com/chihebchebbi/Microsoft-Defender-XDR-KEV-Mapper 

# Navigate to the project directory
cd Microsoft-Defender-XDR-KEV-Mapper 

# Install the required Library pandas
pip3 install pandas, termcolor
```

## Configuration
Before using the tool, update the following parameters in `Config.toml` located in the `Config` folder:
```toml
Client_ID = "Client_ID_Here"
Client_Secret = "Client_Secret_Here"
EntraID_Tenant = "EntraID_Tenant_Here"
```

