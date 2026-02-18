Persistence via Registry/Startup
=================================

Description of Use Case
------------------------
This was a very specialized use case where the top-performing log sources were those designed with the explicit purpose of monitoring for system configuration changes. General-purpose logs were far less effective. The results show a clear preference for telemetry that provides high-fidelity "before and after" states or real-time modification alerts.


Techniques Evaluated
---------------------
* T1547 Boot or Logon Autostart Execution
* T1112 Modify Registry
* T1053 Scheduled Task/Job
* T1543 Create or Modify System Process
* T1546 Event Triggered Execution
* T1574 Hijack Execution Flow
* T1197 BITS Jobs


Top Scoring Log Sources
-------------------------
.. table::

   +------------------------------------------------------+-------+
   | Log Source                                           | Score |
   +======================================================+=======+
   | EDR: Telemetry                                       | 27.7  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 12/13/14: Registry Events                | 27.0  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 13: Registry Value Set                   | 27.0  |
   +------------------------------------------------------+-------+
   | EDR: Registry Modifications                          | 26.0  |
   +------------------------------------------------------+-------+
   | Autoruns Data                                        | 26.0  |
   +------------------------------------------------------+-------+
   | Windows Security: EID 4657                           | 24.6  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 1: Process Create                        | 24.3  |
   +------------------------------------------------------+-------+
   | Windows PowerShell: EID 4104: Script Block Logging   | 24.3  |
   +------------------------------------------------------+-------+
   | Windows Security: EID 4663: Process Creation         | 23.3  |
   +------------------------------------------------------+-------+
   | Other Platform / Application Logs                    | 22.3  |
   +------------------------------------------------------+-------+


Key Trends & Generalizations
------------------------------
* **Specificity is Paramount**: This use case proves that a specialized tool for a narrow job (like Autoruns or Sysmon's registry monitoring) is often more valuable than a general-purpose log that happens to catch some of the activity.

* **There is a Place for Snapshot Analysis**: Not all security data needs to be real-time. The high score of Autoruns demonstrates that periodic, high-fidelity snapshots are extremely effective for non-urgent but critical tasks like persistence hunting.

* **The Action is on the Endpoint**: Similar to Lateral Movement, network data is almost completely irrelevant for detecting this category of persistence. The entire story is told through file, registry, and process events on the host itself.


Evaluation of Log Source Types
-------------------------------
Registry modification events were the clear #1 category. File creation events (for startup folders) were a strong #2. Process creation events were #3, useful for seeing the actor but not the persistence artifact itself.

**Technology Comparison: EDR ≈ Sysmon > Specialized Tools (Autoruns) > Native Windows Logs**


Scoring Data
-------------
The raw TC scores broken down by metric can be found here: :download:`Persistence via Registry/Startup<FinalConfidenceScores_Persistence via Registry.csv>`
