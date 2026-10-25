# Windows Security Log Analysis with Splunk

## Overview

This project investigates Windows security events using Splunk Enterprise. The objective is to analyse failed logon attempts, identify source IP activity, review usernames involved in authentication failures, and examine the timeline of successful and failed logons.

## Tools Used

- Splunk Enterprise
- Search Processing Language (SPL)
- Windows Event Log sample dataset
- GitHub

## Dataset

- **File:** `windows_event.csv`
- **Source:** [SOC Sample Logs](https://github.com/SreejithReji/soc-sample-logs)
- **Data type:** Simulated security log data for educational purposes

## Investigation Steps

1. Imported the CSV dataset into Splunk.
2. Searched for failed logon events using Event ID `4625`.
3. Aggregated failed logons by username, source IP, and status.
4. Identified source IPs associated with multiple usernames.
5. Reviewed successful logon events using Event ID `4624`.
6. Examined the timeline of successful and failed logons for a selected source IP.

## Findings

- The failed logon search returned 100 events in the displayed results.
- Source IP `185.220.101.45` appeared in the failed logon results.
- Seven distinct usernames were associated with the failed logon events from this source IP.
- Successful logon events associated with the same source IP were also observed and reviewed in the timeline.

These findings indicate authentication activity that warrants further investigation within the sample dataset. They do not, by themselves, confirm account compromise or a successful attack.

## Sample SPL Queries

### Failed Logons by Username and Source IP

```spl
index=main source="windows_event.csv" EventID=4625
| stats count by Username SourceIP Status
| sort - count
```

### Failed Logons by Source IP

```spl
index=main source="windows_event.csv" EventID=4625
| stats count dc(Username) as unique_usernames values(Username) as usernames by SourceIP
| sort - count
```

### Authentication Timeline

```spl
index=main source="windows_event.csv" (EventID=4624 OR EventID=4625) SourceIP="185.220.101.45"
| table _time EventID Username SourceIP Status
| sort _time
```

## Screenshots

1. `screenshots/01-data-ingestion.png`
2. `screenshots/02-failed-login-analysis.png`
3. `screenshots/03-failed-logins-by-source-ip.png`
4. `screenshots/04-login-investigation-timeline.png`

## Limitations

- The dataset is simulated and is not evidence of a real-world security incident.
- Authentication events require context before they can be classified as malicious.
- The timeline and event fields should be validated against the original records before drawing definitive conclusions.
- Additional investigation would be needed to establish whether the successful logons were related to the failed attempts.

## Skills Practised

- Windows authentication log analysis
- Splunk SPL queries
- Event ID investigation
- Source IP and username correlation
- Security event timeline review
- Technical documentation and evidence reporting

## Disclaimer

This project is for educational and portfolio purposes. Findings are limited to the supplied sample dataset and should not be interpreted as confirmation of a real security breach.
