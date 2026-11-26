# Cybersecurity Investigation Portfolio

End-to-end SOC threat investigations, PCAP network forensics, malware static analysis, and incident response reports mapped to MITRE ATT&CK and the NIST IR Lifecycle.

## Threat Investigations & Incident Response

| Investigation | Primary Tools | MITRE ATT&CK / Framework | Summary | Report |
| :--- | :--- | :--- | :--- | :--- |
| **NetSupport RAT — PCAP Forensics & Static Analysis** | Wireshark, REMnux | `T1059.001` • `T1059.006` • `T1027.003` • `T1036.008` • `T1219` • `T1571` | Traced an 18-second NetSupport RAT infection on `DESKTOP-5OMVI3L` via PCAP analysis; carved HTTP payloads (`stage1.ps1`, `5555.mp4`) and decoded `worker.py` to uncover MP4 `uuid`-box steganography and cleartext HTTP C2 over `TCP/443`. | [View Report →](./Incident_TheLuckyTurkey_NetSupport_RAT/) |
| **Incident CoCanDa: Spear-Phishing & Payload Analysis** | Static & Forensic Triage | NIST IR Lifecycle | End-to-end forensic investigation, indicator extraction, and executive remediation reporting. | [View Report →](./Incident_CoCanDa/) |
