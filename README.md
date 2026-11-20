# Cybersecurity Investigation Portfolio

End-to-end SOC threat investigations, PCAP network forensics, malware static analysis, and incident response reports mapped to MITRE ATT&CK and the NIST IR Lifecycle.

## Threat Investigations & Incident Response

| Investigation | Primary Tools | MITRE ATT&CK / Framework | Summary | Report |
| :--- | :--- | :--- | :--- | :--- |
| **NetSupport RAT — PCAP Forensics & Static Analysis** | Wireshark, REMnux | `T1059.001` • `T1059.006` • `T1027.003` • `T1036.008` • `T1219` • `T1571` | Traced an 18-second NetSupport RAT infection on `DESKTOP-5OMVI3L` via PCAP analysis; carved HTTP payloads (`stage1.ps1`, `5555.mp4`) and decoded `worker.py` to uncover MP4 `uuid`-box steganography and cleartext HTTP C2 over `TCP/443`. | [View Report →](./Incident_TheLuckyTurkey_NetSupport_RAT/) |
| **Ransomware & Domain Controller Compromise** | SIEM / Endpoint Logs | `T1566` • `T1053` • `T1078` • `T1018` • `T1021` • `T1074` • `T1486` | Mapped a full intrusion from phishing PDF and LOLBin execution to AV impairment, `nslookup` discovery, RDP lateral movement, `1.7z` data staging, and ransomware impact. | [View Case Study →](./01-Ransomware-DC-Compromise/) |
| **Endpoint Backdoor & Privilege Escalation Triage** | SIEM / Windows Event Logs | `T1078` • `T1136` • `T1562` | Investigated compromised credentials (`kporter`) creating an unauthorized `evil` account and modifying firewall rules; documented NIST containment, eradication, and recovery steps. | [View Case Study →](./02-Endpoint-Backdoor-Triage/) |
| **Incident CoCanDa: Spear-Phishing & Payload Analysis** | Static & Forensic Triage | NIST IR Lifecycle | End-to-end forensic investigation, indicator extraction, and executive remediation reporting. | [View Report →](./Incident_CoCanDa/) |
