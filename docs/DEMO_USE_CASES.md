# FortiAnalyzer MCP Server - Demo Use Cases

12 practical use cases demonstrating the main capabilities of the FortiAnalyzer MCP Server.

---

## Use Case 1: System Health Check
**Module:** System Tools

**Scenario:** Quick overview of FortiAnalyzer status and managed devices.

**Prompt:**
```
What is the current FortiAnalyzer system status? List all devices being managed and show me the HA cluster status.
```

**Tools Used:**
- `get_system_status`
- `list_devices`
- `get_ha_status`

**Expected Output:** FortiAnalyzer version, uptime, platform info, list of managed FortiGates, HA sync status.

---

## Use Case 2: Traffic Analysis - Top Bandwidth Consumers
**Module:** FortiView Analytics

**Scenario:** Identify which internal hosts are consuming the most bandwidth.

**Prompt:**
```
Show me the top 10 bandwidth consumers in the last 24 hours. Include source IP, total bytes, and number of sessions.
```

**Tools Used:**
- `get_top_sources`

**Expected Output:** Ranked list of source IPs with bandwidth usage, helping identify heavy users or potential data exfiltration.

---

## Use Case 3: Security Threat Investigation
**Module:** FortiView Analytics + Log Tools

**Scenario:** Investigate security threats detected in the network.

**Prompt:**
```
What are the top security threats detected in the last 7 days? For the most critical one, show me the related log entries.
```

**Tools Used:**
- `get_top_threats`
- `search_security_logs`

**Expected Output:** List of threats by severity, detailed logs showing attack source, target, and action taken.

---

## Use Case 4: Generate Executive Report
**Module:** Report Tools

**Scenario:** Generate a bandwidth and applications report for management review.

**Prompt:**
```
List available report layouts. Then run the "Bandwidth and Applications Report" for the last 30 days and save it as PDF to my Downloads folder.
```

**Tools Used:**
- `list_report_layouts`
- `run_and_wait_report`
- `save_report`

**Expected Output:** PDF report saved to ~/Downloads with bandwidth statistics, top applications, and usage trends.

---

## Use Case 5: Alert Triage and Response
**Module:** Event/Alert Tools

**Scenario:** SOC analyst reviewing and responding to security alerts.

**Prompt:**
```
Show me all unacknowledged security alerts from the last 24 hours. For any critical alerts, show me the associated logs and add a comment that I'm investigating.
```

**Tools Used:**
- `get_alerts`
- `get_alert_logs`
- `add_alert_comment`
- `acknowledge_alerts`

**Expected Output:** List of alerts, detailed log context, confirmation of comments added and alerts acknowledged.

---

## Use Case 6: Application Visibility
**Module:** FortiView Analytics

**Scenario:** Understanding what applications are being used across the network.

**Prompt:**
```
What are the top 10 applications by bandwidth in the last hour? Also show me the top cloud/SaaS applications being accessed.
```

**Tools Used:**
- `get_top_applications`
- `get_top_cloud_applications`

**Expected Output:** Ranked applications list (YouTube, Microsoft 365, Zoom, etc.) with bandwidth and session counts.

---

## Use Case 7: Incident Creation and Tracking
**Module:** Incident Management

**Scenario:** Creating a security incident from detected anomalies.

**Prompt:**
```
Create a new security incident named "Suspicious Outbound Traffic from Server-01" with high severity. Then show me all open incidents and their statistics.
```

**Tools Used:**
- `create_incident`
- `get_incidents`
- `get_incident_stats`

**Expected Output:** Incident created with ID, list of all incidents, statistics by severity and status.

---

## Use Case 8: Log Search - Specific IP Investigation
**Module:** Log Tools

**Scenario:** Investigating traffic from a specific suspicious IP address.

**Prompt:**
```
Search for all traffic logs involving IP address 10.0.1.50 in the last 24 hours. Show me source, destination, port, action, and bytes transferred.
```

**Tools Used:**
- `search_traffic_logs`

**Expected Output:** Filtered log entries showing all network activity for the specified IP, helping identify communication patterns.

---

## Use Case 9: Web Usage Analysis
**Module:** FortiView Analytics

**Scenario:** Reviewing web browsing patterns and policy effectiveness.

**Prompt:**
```
Show me the top 20 websites accessed today. Also show me the firewall policy hit counts to see which rules are being triggered most.
```

**Tools Used:**
- `get_top_websites`
- `get_policy_hits`

**Expected Output:** Most visited websites with bandwidth, policy rules ranked by hit count showing rule effectiveness.

---

## Use Case 10: Device Inventory and Health
**Module:** Device Management + System Tools

**Scenario:** Audit of managed devices and their status.

**Prompt:**
```
List all FortiGate devices managed by this FortiAnalyzer. For each device, show me the firmware version and connection status. Are there any devices that are offline?
```

**Tools Used:**
- `list_devices`
- `get_device_info`
- `search_devices` (with connection_status filter)

**Expected Output:** Complete device inventory with versions, identification of any offline or outdated devices.

---

## Use Case 11: PCAP Download for Forensics
**Module:** PCAP Tools

**Scenario:** Security analyst needs to download packet captures for IPS events for forensic analysis.

**Prompt:**
```
Search for critical IPS attacks in the last 7 days. List the ones that have PCAP files available. Then download the PCAP for the most recent attack.
```

**Tools Used:**
- `search_ips_logs`
- `list_available_pcaps`
- `get_pcap_by_session`

**Expected Output:** List of critical IPS events with session IDs, PCAP downloaded to ~/Downloads folder.

---

## Use Case 12: Bulk PCAP Collection
**Module:** PCAP Tools

**Scenario:** Collect all packet captures for attacks from a specific source IP for incident response.

**Prompt:**
```
Download all available PCAPs for IPS attacks from source IP 192.168.1.100 in the last 24 hours.
```

**Tools Used:**
- `search_and_download_pcaps`

**Expected Output:** Multiple PCAP files downloaded, summary showing download count, skipped files, and any failures.

---

## Quick Demo Commands Summary

| # | Use Case | Key Prompt |
|---|----------|------------|
| 1 | System Health | "What is the FortiAnalyzer system status?" |
| 2 | Bandwidth Analysis | "Show me top 10 bandwidth consumers" |
| 3 | Threat Investigation | "What are the top security threats?" |
| 4 | Executive Report | "Generate a bandwidth report for last 30 days" |
| 5 | Alert Triage | "Show unacknowledged alerts and investigate" |
| 6 | Application Visibility | "What applications are using the most bandwidth?" |
| 7 | Incident Management | "Create a security incident for suspicious traffic" |
| 8 | IP Investigation | "Search logs for IP 10.0.1.50" |
| 9 | Web Usage | "Show top websites and policy hits" |
| 10 | Device Audit | "List all managed devices and their status" |
| 11 | PCAP Forensics | "Download PCAP for critical IPS attack" |
| 12 | Bulk PCAP Collection | "Download all PCAPs from source IP" |

---

## Demo Tips

1. **Start Simple:** Begin with Use Case 1 (System Health) to verify connectivity
2. **Show Natural Language:** Emphasize that prompts are conversational, not commands
3. **Highlight Follow-ups:** Show how Claude can drill down (e.g., "Tell me more about that threat")
4. **Real Data:** Use actual data from your FortiAnalyzer for more impactful demos
5. **Report Download:** Use Case 4 is visually impressive - show the actual PDF opening

## Modules Covered

- ✅ System Tools (Use Cases 1, 10)
- ✅ Device Management (Use Case 10)
- ✅ Log Tools (Use Cases 3, 8)
- ✅ Report Tools (Use Case 4)
- ✅ FortiView Analytics (Use Cases 2, 3, 6, 9)
- ✅ Event/Alert Tools (Use Case 5)
- ✅ Incident Management (Use Case 7)
- ✅ PCAP Tools (Use Cases 11, 12)
- ⬜ IOC Tools (not included - requires specific license)
