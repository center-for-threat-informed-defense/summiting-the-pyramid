Summit the Pyramid
==================
Updated: 05/26/2023

Goal of Summiting the Pyramid
-----------------------------
The Pyramid of Pain has been used by detection engineers to determine the cost or “pain” it would take for an adversary to evade defenses 
that are effective at that level of the pyramid. Starting at the bottom, changing indicators of hash values, IP addresses, and domains are 
trivial for an adversary to change and continue their attack. Indicators further up the pyramid are more difficult for an adversary to 
change and consume more time and money from the adversary. Finally, Tactics, Techniques, and Procedures (TTPs), outlined by the MITRE 
ATT&CK Framework, describe an adversary’s behavior when achieving their goals. New TTPs are the hardest for adversaries to develop, 
as behaviors are limited by the environment they are acting in.

.. figure:: _static/pyramid_of_pain.png
   :alt: Pyramid of Pain - Created by David Bianco
   :align: center

   Pyramid of Pain - Created by David Bianco [#f1]_

Detection engineers can leverage the Pyramid of Pain to understand how :ref:`precise<Precision>` or :ref:`robust<Robustness>` their analytics are when detecting adversarial 
behavior. A detection analytic focused on identifying hash values will be precise in detecting a snapshot of malware but will not detect a 
variant of that malware that has been altered by an adversary. A detection at the tool level might be robust in detecting specific 
implementations of a technique but could create more false positives, pick benign user activity, and alert on system generated noise if the implemented tool is native to 
the OS. Some analytics might use a combination of various indicators to increase both the precision and :ref:`recall<Recall>` of an adversary attack. 

:ref:`Capability Abstraction`, a concept developed by SpecterOps `SpecterOps <https://posts.specterops.io/capability-abstraction-fbeaeeb26384>`_., seeks to understand activities that occur on a system when an attacker is 
accomplishing their goals. It also introduced a visual graphic, known as an “abstraction map”, which conveys the relationships between 
abstraction layers and begins to highlight how an adversary can evade a specific detection or data source entirely and still accomplish their goals. The following capability abstraction map for `T1543 - Create or Modify System Process: Windows Service <https://attack.mitre.org/techniques/T1543/003/>`_, illustrates how multiple tools can create a new service.

.. figure:: _static/new_service_capability_abstraction.png
   :alt: New Service Capability Abstraction - Created by SpecterOps
   :align: center

   New Service Capability Abstraction - Created by SpecterOps [#f3]_

These tools include 
standard Windows binaries, commonly abused binaries, and open-source implementations that an adversary may implement in custom code. These different 
implementations may call the Windows API differently, which in turn might call different RPC interface and methods. However, ultimately they 
all utilize the same registry key within the Registry Service Database. If an adversary wanted to evade detection at the tool level, they 
could create a new service by directly interacting with the Windows API, RPC, or Registry. This is not a hypothetical, but has actually been seen in the wild. Threat group APT41 has utilized Windows service creation within their attacks not only through the utilization of the service creation tool (sc.exe), but also by directly modifying the registry itself [#f2]_. **Understanding that adversaries will attempt attacks at different parts in the OS, defenders must understand where their analytics are detecting this activity.**

Levels and Observables
----------------------
The Table of Levels and Observables shows the relationship between indicators used to detect adversary activities and robustness 
of resulting analytics in order to determine relative complexity of evasion. When analytics are created, the question should be asked, “How 
difficult would it be for an adversary to evade this analytic?” The Pyramid of Pain shows us how difficult it is for an adversary to change 
their behavior. These levels will focus on understanding how some analytic observables are more evadable or more difficult to bypass than 
others, resulting in more robust analytics which detect activity deeper in the OS.

+-------------------------------+---------------------------------+
| Level                         | Observable Categories           |
+===============================+=================================+
| Kernel/Interfaces             |                                 |                              
|                               |                                 |                             
+-------------------------------+---------------------------------+
| System Calls                  |  | File manipulation            |                              
|                               |  | Communication protection     |                              
|                               |  | Native API calls             |                              
|                               |  | Trap instructions            |                                                          
+-------------------------------+---------------------------------+
| OS API                        |  | API calls                    |                                                        
+-------------------------------+---------------------------------+
| Library API                   |  | .NET Framework               |                              
|                               |  | DLLs                         |                              
|                               |  | COM methods                  |                              
+-------------------------------+---------------------------------+
| Tools Outside Adversary       |  | Signatures                   |                              
| Control                       |  | Command-line arguments       |                              
|                               |  | Tool-specific configurations |                              
+-------------------------------+---------------------------------+
| Tools Within Adversary        |  | Signatures                   |                              
| Control                       |  | Command-line arguments       |                              
|                               |  | Tool-specific configurations |                              
+-------------------------------+---------------------------------+
| Operational/Environmental     |  | Hash values                  |                              
| Variables                     |  | IP addresses                 |                              
|                               |  | Protocol-specific ports      | 
|                               |  | Filenames                    | 
|                               |  | Domain names                 |                              
+-------------------------------+---------------------------------+

The :ref:`levels and observables<Levels Definitions>` are used to inform defenders about the state of their analytic, it is not meant to imply judgement of certain analytics. As 
Jared Atkinson mentioned in his write-up on the Detection Spectrum, “There is a place for precise detections just like there is a place for 
broad detections” [#f4]_. These levels are used to inform how defenders can utilize observables deeper in the OS to create less evade-able analytics, saving time, resources, and analyst workload. This can be 
used not only to create new analytics, but to improve current detections by reducing dependencies on lower levels on the Pyramid of Pain and 
the lower levels listed here. By identifying where analytics fall within the table or levels and observables and improving lower level analytics, defenders can ensure that their defenses cover multiple areas of the OS and detect potential evasion efforts made by adversaries.

Example: :ref:`ADFind.exe <AD Find>`
------------------------------------

.. list-table::
    :widths: 30 70

    * - Original Analytic
      - | CommandLine|contains:
        |   - 'objectcategory'
        |   - 'trustdmp'
        |   - 'dcmodes'
        |   - 'dclist'
        |   - 'computers_pwdnotreqd'
        | Image|endswith: '\\adfind.exe'

For example, this analytic  looks for specific command line arguments used in conjunction with the ADFind tool [#f5]_, identified by ‘\adfind.exe’ within the image path. Looking at the levels and observables, we can begin to place where everything is. First, we place Image|endswith: ‘\\adfind.exe’ within the **Operational and Environmental Variables** level. While the intention of this analytic is looking for the execution of the adfind tool, the image path can be obfuscated by adversaries within the command line. We put the command line arguments into the **Tools Within Adversary Control** level, since these command line arguments are specific to the tool itself. The final placement of the analytic is below.

.. list-table::
    :widths: 15 30 60
    :header-rows: 1

    * - Level
      - Level Name
      - Observables
    * - 7
      - Kernel/Interfaces
      - 
    * - 6
      - System Calls
      - 
    * - 5
      - OS API
      - 
    * - 4
      - Library API
      - 
    * - 3
      - Tools Outside Adversary Control
      - 
    * - 2
      - Tools Within Adversary Control
      - | CommandLine|contains:
        |   - 'objectcategory'
        |   - 'trustdmp'
        |   - 'dcmodes'
        |   - 'dclist'
        |   - 'computers_pwdnotreqd'
    * - 1
      - Operational/Environmental Variables
      - Image|endswith: '\\adfind.exe'

This analytic could be easily evaded by adversaries if they were to rename the binary. **How can we improve this analytic so it is more robust?** We don’t need to improve it down all the way to the system application or kernel level, so let’s take it one step at a time.

As mentioned previously, adversaries can change the image name so detection tools do not detect the real tool they are attempting to use. However, adversaries must declare the tool they are using somewhere. Adversaries can compile tools with their corresponding filepath into their software in order to know where to find the specific file to use. This means that compared to utilizing this tool within the command line, the filepath cannot be obfuscated in the code. It must have the correct filepath to point to for use within the software within the PE header. File attributes can be parsed and identified through the data source **OriginalFileName**, a data source that is available through parsing in Sysmon. By tracking the file attribute rather than the image name, we can identify the tool the adversary is going to use. We can make the analytic improvements here.

.. list-table::
    :widths: 15 30 60
    :header-rows: 1

    * - Level
      - Level Name
      - Observables
    * - 7
      - Kernel/Interfaces
      - 
    * - 6
      - System Calls
      - 
    * - 5
      - OS API
      - 
    * - 4
      - Library API
      - 
    * - 3
      - Tools Outside Adversary Control
      - 
    * - 2
      - Tools Within Adversary Control
      - | CommandLine|contains:
        |   - 'objectcategory'
        |   - 'trustdmp'
        |   - 'dcmodes'
        |   - 'dclist'
        |   - 'computers_pwdnotreqd'
        | OriginalFileName: 'adfind.exe'
    * - 1
      - Operational/Environmental Variables
      - 

Through this process, we have improved our analytic by just changing one field to identify adversary behavior and make it more difficult for them to evade detection of this analytic. To evade this improved analytic, and adversary must use a hex editor to change the filepath pointing to adfind. This highlights the importance of being able to go up the levels and identify different areas for improvement. Not everyone is going to be able to collect Sysmon data or make these analytic improvements. However, it gets us thinking of where we can begin to make these small, incremental steps within our environment to create more robust analytics.

Assumptions and Caveats
-----------------------
* Our current guidance addresses data sources and levels within Windows systems. There is definitely room to create guidance for networks, cloud, virtual machines, and other platform types to improve analytics across various platforms. We will attempt to begin guidance for these other platforms, but is open to future work.
* The levels and observables currently defined by Summiting the Pyramid address the robustness of analytics, compared to precision and recall. To read more, :ref:`read this entry here <Robustness Precision Recall>`.
* Tampering is a big part of an adversary attack. If an adversary can’t go any further to evade a specific analytic, they may try to use tampering to accomplish their goal. Switching from evasion to tampering increases cost for the adversary, which is a victory for the defender. The StP team will be cognizant of this as we continue to draft best practice guidance, and though a more detailed study of when an adversary changes tactic to tampering may be out of scope for this initial effort, it may be prime for future work.

**We are always looking for feedback and integrating your thoughts and ideas! Please feel free to leave comments on the GitHub, or reach out to Ross or Roman.**

.. rubric:: References

.. [#f1] http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
.. [#f2] https://www.mandiant.com/resources/blog/apt41-initiates-global-intrusion-campaign-using-multiple-exploits
.. [#f3] https://abstractionmaps.com/maps/t1050/
.. [#f4] https://posts.specterops.io/detection-spectrum-198a0bfb9302
.. [#f5] https://github.com/SigmaHQ/sigma/blob/30bee7204cc1b98a47635ed8e52f44fdf776c602/rules/windows/process_creation/win_susp_adfind.yml
