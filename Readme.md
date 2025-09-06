# 🧠 DNS Log Analysis with Splunk SIEM

A hands-on guide for uploading, parsing, and analyzing structured DNS log files using **Splunk SIEM**. This project demonstrates how to ingest DNS logs with 23 fields, extract meaningful insights, and detect anomalies or threats.

---

## 📂 Project Structure

dns-log-analysis-splunk/
├── sample_dns_logs.log # Sample DNS log file (23 fields)
├── field_extraction_rex.txt # REX expression for Splunk field extraction
├── queries/
│ ├── top_queries.spl # SPL for top domains queried
│ ├── anomaly_detection.spl # SPL to detect spikes or anomalies
│ ├── suspicious_domains.spl # SPL to find known bad domains
├── dashboards/ # (Optional) SPL for Splunk dashboards
└── README.md

---

## 📊 About the DNS Log Format

Each log line contains **23 tab-separated fields**, including:

- `timestamp`, `session_id`, `src_ip`, `dst_ip`, `query_name`, `record_type`, TTL, flags, and more.

### Example:

```text
1331901006.800000	Cgrcup1c5uGRx428V7	192.168.202.93	60821	172.19.1.100	53	udp	3550	www.apple.com	1	C_INTERNET	28	AAAA	-	-	F	F	T	F	0	-	-	F
✅ Prerequisites

Splunk Enterprise or Splunk Free installed

Access to Splunk Web UI

Sample DNS logs (.log or .txt)

A custom source type (e.g., dns_sample)
🚀 Getting Started
1. Upload DNS Logs to Splunk

Open Splunk Web → Settings > Add Data

Choose Upload and select sample_dns_logs.log

Assign sourcetype: dns_sample

Choose or create an index (e.g., dns_index)

Complete the wizard and ingest the file

2. Extract Fields with REX

Use the following rex command to extract all 23 fields:
| rex field=_raw "^(?<timestamp>\d+\.\d+)\s+(?<session_id>\S+)\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<src_port>\d+)\s+(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<dst_port>\d+)\s+(?<protocol>\S+)\s+(?<transaction_id>\d+)\s+(?<query_name>\S+)\s+(?<query_count>\d+)\s+(?<query_class>\S+)\s+(?<ttl>\d+)\s+(?<record_type>\S+)\s+(?<field14>\S+)\s+(?<field15>\S+)\s+(?<flag1>[FT])\s+(?<flag2>[FT])\s+(?<flag3>[FT])\s+(?<flag4>[FT])\s+(?<response_code>\d+)\s+(?<field21>\S+)\s+(?<field22>\S+)\s+(?<final_flag>[FT])"
🔍 Useful SPL Queries
Top Queried Domains and Source IPs
index=dns_index sourcetype=dns_sample
| rex <your full rex here>
| top query_name, src_ip

DNS Query Trends Over Time
index=dns_index sourcetype=dns_sample
| rex <rex>
| timechart span=10m count by src_ip

Suspicious or Known Bad Domains
index=dns_index sourcetype=dns_sample
| rex <rex>
| search query_name IN ("maliciousdomain.com", "badguy.net")
