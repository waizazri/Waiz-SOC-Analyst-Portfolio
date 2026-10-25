# Windows Security Log Analysis with Splunk

## 1. Overview

This project demonstrates a basic security investigation workflow using Splunk Enterprise to analyse Windows authentication events.

The investigation focuses on failed logon attempts, source IP activity, usernames involved in authentication failures, and the relationship between failed and successful logon events.

The objective is to identify suspicious authentication patterns and document findings using evidence from the dataset.

## 2. Tools and Technologies

- Splunk Enterprise
- Search Processing Language (SPL)
- Windows Event Log sample dataset
- GitHub

## 3. Dataset

- **File:** `windows_event.csv`
- **Source:** [SOC Sample Logs](https://github.com/SreejithReji/soc-sample-logs)
- **Format:** CSV
- **Purpose:** Educational security log analysis

The dataset contains simulated security events. The findings in this project apply only to the supplied sample data.

## 4. Investigation Methodology

The investigation followed these steps:

1. Imported `windows_event.csv` into Splunk.
2. Searched for failed logon events using Windows Event ID `4625`.
3. Grouped failed logon events by username, source IP address, and status.
4. Identified source IP addresses associated with multiple usernames.
5. Reviewed successful logon events using Event ID `4624`.
6. Examined the timeline of failed and successful logon events associated with a selected source IP.
7. Documented the findings and limitations of the investigation.

## 5. Key Findings
