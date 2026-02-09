Data Exfiltration via Web/Cloud
================================

Description of Use Case
------------------------
The scoring for this use case overwhelmingly favored specialized security tools that can inspect the content of data and understand cloud-native applications. General-purpose network and OS logs, while providing broad coverage, consistently scored lower due to a lack of deep, contextual insight. The highest scores were achieved by sources that could answer "What data left?" not just "Did data leave?".


Techniques Evaluated
---------------------
* T1567 Exfiltration Over Web Service
* T1041 Exfiltration Over C2 Channel
* T1071 Application Layer Protocol
* T1132.001 Data Encoding: Standard Encoding
* T1102.001 Web Services: Bidirectional Communications
* T1020 Automated Exfiltration
* T1048 Exfiltration Over Alternative Protocol
* T1056 Archive Collected Data
* T1001 Data Obfuscation
* T1537 Transfer Data to Cloud Account


Top Scoring Log Sources
-------------------------
.. table::

   +------------------------------------------------------+-------+
   | Log Source                                           | Score |
   +======================================================+=======+
   | DLP (Data Loss Prevention) Alerts                    | 28.7  |
   +------------------------------------------------------+-------+
   | EDR: Data Exfil Heuristics                           | 27.1  |
   +------------------------------------------------------+-------+
   | CASB (Cloud Access Security Broker) Logs             | 26.4  |
   +------------------------------------------------------+-------+
   | EDR: Suspicious Child Process                        | 26.7  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 8: CreateRemoteThread                    | 26.0  |
   +------------------------------------------------------+-------+
   | EDR / Endpoint Telemetry                             | 25.8  |
   +------------------------------------------------------+-------+
   | AWS: GuardDuty Findings                              | 25.8  |
   +------------------------------------------------------+-------+
   | Azure: Sentinel Detections                           | 25.8  |
   +------------------------------------------------------+-------+
   | GCP: Security Command Center Findings                | 25.8  |
   +------------------------------------------------------+-------+
   | EDR: Remote Access Software Detections               | 25.3  |
   +------------------------------------------------------+-------+


Key Trends & Generalizations
------------------------------
* **Content is King**: For data exfiltration, visibility into the data itself is the single most important factor. Telemetry sources that can apply rules, signatures, or classifications to data in transit score the highest.

* **Perimeter is Not Enough**: Relying solely on traditional firewall or NetFlow logs is insufficient. Adversaries easily blend exfiltration into legitimate web and cloud traffic (HTTPS), making deep packet or application-layer inspection (TLS inspection, CASB) a necessity.

* **Behavioral Analytics Outperform Raw Logs**: The high score of "EDR: Data Exfil Heuristics" shows that a system which can correlate multiple events (e.g., file access > compression > upload) provides a much stronger signal than any of those single events alone.


Evaluation of Log Source Types
-------------------------------
Content-aware alerts (DLP, CASB) were the undisputed champions. Network traffic metadata (NetFlow, Firewall logs) ranked significantly lower, establishing a clear pattern: seeing the content and destination context is more valuable than seeing the volume and connection data alone. Process events were middle-tier: useful for seeing a tool like 7z.exe run, but not for seeing the data leave.

**Technology Comparison: Specialized Security Tools (DLP, CASB, EDR) >> Cloud-Native Security >> Native OS / Network Gear**