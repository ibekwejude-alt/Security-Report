# Cybersecurity Investigation Portfolio

End-to-end SOC threat investigations, PCAP network forensics, malware static analysis, and incident response reports mapped to MITRE ATT&CK and the NIST IR Lifecycle.

## Threat Investigations & Incident Response

| Investigation | Primary Tools | MITRE ATT&CK / Framework | Summary | Report |
| :--- | :--- | :--- | :--- | :--- |
| **FormBook Info-Stealer — C2 & Exfiltration Analysis** | Wireshark, tshark, REMnux | `T1071.001` • `T1041` • `T1568` • `T1001` | Investigated an active FormBook infection on `DESKTOP-5NLV63K` (`172.16.8.49`); attributed the victim via Kerberos and UTF-16LE `strings`, isolated the active C2 (`38.182.168[.]246`) from 14 decoy domains using `tshark` HTTP response-code analysis, and verified zero lateral spread. | [View Report →](./01_Incident_FirstToLast_FormBook/README.md) |
| **NetSupport RAT — PCAP Forensics & Static Analysis** | Wireshark, REMnux | `T1059.001` • `T1059.006` • `T1027.003` • `T1036.008` • `T1219` • `T1571` | Traced an 18-second NetSupport RAT infection on `DESKTOP-5OMVI3L` via PCAP analysis; carved HTTP payloads (`stage1.ps1`, `5555.mp4`) and decoded `worker.py` to uncover MP4 `uuid`-box steganography and cleartext HTTP C2 over `TCP/443`. | [View Report →](./02_Incident_TheLuckyTurkey_NetSupport_RAT/) |
| **Incident CoCanDa: Spear-Phishing & Payload Analysis** | Static & Forensic Triage | NIST IR Lifecycle | End-to-end forensic investigation, indicator extraction, and executive remediation reporting. | [View Report →](./03_Incident_CoCanDa/) |
