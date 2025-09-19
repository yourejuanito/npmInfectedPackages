# npmInfectedPackages
npm shai hulud detector workflow for jamf pro. 


## Overview
Being security-conscious, this project provides a workflow for identifying Jamf Pro–managed devices that may contain **infected npm packages**.  
It uses the published list of compromised packages from [Endor Labs](https://www.endorlabs.com/learn/npm-malware-outbreak-tinycolor-and-crowdstrike-packages-compromised) and integrates directly into Jamf Pro to detect exposure.

## Features
- Detects devices with Node.js installed (native installer or Homebrew).  
- Compares installed npm packages against a curated list of known compromised packages.  
- Reports results back to Jamf Pro:  
  - **CLEAR** when no impacted packages are found.  
  - A list of infected packages when matches are detected.  
- Includes Extension Attributes, scripts, and packaging instructions for easy deployment.

## Components
- **EA-NodejsVersion**  
  - Identifies whether Node.js is installed, regardless of install method (installer or Homebrew).  
- **EA-NodejsStatus**  
  - Reports device state: `CLEAR` or lists infected npm packages if found.  
- **malware_report.csv**  
  - CSV of impacted npm packages (from Endor Labs). As days go by there may be more packages added to the list make sure you also verify that the list is up to date.
- **npm_detector.py**  
  - Core Python detector script.  
- **npmDetector-unsigned.pkg**  
  - Prebuilt package containing the CSV and detector script.  
  - ⚠️ Run through [Suspicious Package](https://mothersruin.com/software/SuspiciousPackage/) before use to verify contents.  
- **script-npmDetector.sh**  
  - Jamf-ready wrapper to execute the detector on endpoints.

## Deployment Steps

### 1. Extension Attributes
Create the following Extension Attributes in Jamf Pro:  
- **EA-NodejsVersion** – identifies devices with Node.js installed.  
- **EA-NodejsStatus** – reports infection status.  

### 2. Package Files
- Package `malware_report.csv` and `npm_detector.py` into:  `/Library/Application Support/Security/inter/`

- Alternatively, upload the included `npmDetector-unsigned.pkg` to Jamf Pro.  

### 3. Jamf Script
- Add a script in Jamf Pro using the provided **script-npmDetector.sh**.  
- Configure it to run **after** other payloads in the policy.  

### 4. Smart Group
- Create a Smart Group for devices that have Node.js installed (using **EA-NodejsVersion** as criteria).  

### 5. Policy
- **Script Payload:** Add `script-npmDetector.sh`.  
- **Package Payload:** Add the uploaded package (either your own or `npmDetector-unsigned.pkg`).  
- Ensure script execution runs **after** package installation.  

## Reporting
- Jamf inventory will show each device’s status:  
- **CLEAR** → No infected npm packages.  
- **IMPACTED** → Device has one or more compromised packages listed.  
- Smart Groups can be built off EA results for targeted remediation.

---

⚠️ **Note:** This workflow is designed only for devices with Node.js installed. Scope your Jamf policy appropriately to avoid unnecessary execution.
