C2 Over Legitimate Channels
============================

Description of Use Case
------------------------
This use case revealed that no single log source is sufficient. The highest scores came from a combination of endpoint and network visibility. Endpoint logs were critical for identifying the "who" and "what" (which process on whose machine), while network logs were essential for seeing the "where" (the destination IP). The very best solutions were those that could correlate these two views.


Techniques Evaluated
---------------------
* T1071 Application Layer Protocol
* T1102 Web Service Protocol
* T1573 Encrypted Channel
* T1090.002 Proxy: External Proxy
* T1105 Ingress Tool Transfer
* T1001 Data Obfuscation
* T1568 Dynamic Resolution
* T1095 Non-Application Layer Protocol
* T1132.001 Data Encoding: Standard Encoding


Top Scoring Log Sources
-------------------------
.. table::

   +------------------------------------------------------+-------+
   | Log Source                                           | Score |
   +======================================================+=======+
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
   | Windows PowerShell: EID 4104: Script Block Logging   | 25.3  |
   +------------------------------------------------------+-------+
   | EDR: API Calls                                       | 25.3  |
   +------------------------------------------------------+-------+
   | EDR: DNS over HTTPS Detection                        | 25.3  |
   +------------------------------------------------------+-------+


Key Trends & Generalizations
------------------------------
* **Correlation is King**: Effective C2 detection is not about a single log source. It's about correlating an endpoint event (a process) with a network event (a connection). The most valuable security platforms are those that make this correlation easy or automatic.

* **DNS is a Critical Investigative Pivot**: While not always the highest-scoring alert, DNS logs (especially from Sysmon EID 22 or Zeek) are the Rosetta Stone for C2 investigations, linking a suspicious IP address back to a domain name that can be researched and tracked.

* **Assume Encryption**: Since most modern C2 traffic uses TLS (HTTPS), detection strategies must account for this. You either need to inspect the encrypted traffic (TLS decryption proxy), analyze its metadata (JA3/JARM hashing, certificate analysis via Zeek), or rely on the endpoint to see the traffic before it's encrypted (EDR).


Evaluation of Log Source Types
-------------------------------
This use case had the most balanced distribution. Process creation, network connection, and DNS logs were all critically important. The highest value came from sources that could link them together. Signature-based network alerts (IDS) also scored very well.

**Technology Comparison: Endpoint (EDR/Sysmon) & Network Security Monitoring (Zeek/Suricata) are co-dependent > Cloud > Windows > Basic Network Gear**


Scoring Data
-------------
The raw TQ scores broken down by metric can be found here: :download:`C2 Over Legitimate Channels<FinalConfidenceScores_C2 Over Legit Channels.csv>`
