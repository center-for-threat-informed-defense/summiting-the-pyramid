Summit the Pyramid
==================
Updated: 07/27/2023

Goal of Summiting the Pyramid
-----------------------------
The Pyramid of Pain [#f1]_ has been used by detection engineers to determine the cost or “pain” it would cause an adversary to evade defenses that are effective at 
that level of the pyramid. Starting at the bottom, changing indicators of hash values, IP addresses, and domains are trivial for an adversary to change and 
continue their attack. Indicators further up the pyramid are more difficult for an adversary to change and consume more time and money from the adversary. 
Finally, Tactics, Techniques, and Procedures (TTPs), outlined by the MITRE ATT&CK Framework, describe an adversary’s behavior when achieving their goals. 
New TTPs are the hardest for adversaries to develop, as behaviors are limited by the environment they are acting in.

.. figure:: _static/pyramid_of_pain.png
   :alt: Pyramid of Pain - Created by David Bianco
   :align: center

   Pyramid of Pain - Created by David Bianco [#f1]_

Detection engineers can leverage the Pyramid of Pain to understand how :ref:`robust<Robustness>` their analytics are when detecting 
adversarial behavior. A detection analytic focused on identifying hash values will be precise in detecting a snapshot of malware but will not detect a variant of 
that malware that has been altered by an adversary. A detection at the tool level might be robust in detecting specific implementations of a technique but could 
create more false positives, pick benign user activity, and alert on system generated noise if the implemented tool is native to the OS. Some analytics might use 
a combination of various indicators to increase both the :ref:`precision<Precision>` and :ref:`recall<Recall>` of an adversary attack. Typically, analytics are quantified by precision (inverse of false alarm rate) and recall (inverse of false negative rate). In this work, we introduce, and focus on improving, a new metric we call :ref:`Robustness`.

.. important::
   Adversaries attack different parts in the OS and might be operating at a level that deployed sensors cannot detect. Therefore, it is imperative that defenders understand 
   where their analytics are detecting activity and the type of activity their analytics are detecting when building robust analytics.

Summiting the Pyramid
---------------------
Let’s break down the pyramid into the different types of activity a defender can build their analytics around. 

The first four levels of the pyramid are focused on ephemeral values which are easy for an adversary to change. The next level is not focused on values, but 
the types of tools an adversary will attempt to use during an attack. Finally, the top level is strictly focused on behaviors which an adversary will demonstrate 
during an attack. These groups can better break down what a defender can focus building their analytic upon. 

.. figure:: _static/pyramid_breakdown_pt1.png
   :alt: Breaking down the Pyramid of Pain
   :align: center

We can further break that down into rows for our model, which will display how to make it more specific for building robust analytics. In each row, we will be 
looking for :ref:`observables<Observable>` upon which we can build analytics for each grouping, based on the difficulty for an adversary to evade.

The bottom row is focused on the first grouping of ephemeral values. These are trivial for an adversary to change, or that change even without adversary intervention. 

The next two rows are split from the tools which can be used by an adversary during an attack. Observables core to an adversary-brought tool are associated with 
tools that are brought in by an adversary to accomplish an attack. Pre-existing tool are tools which are available to defenders before 
adversary use, making it more difficult for an adversary to modify. These two levels were split in recognition of the fact that an adversary will have more control over 
tools they bring to an attack, making it easier for them to evade specific tool detections. Tools which are managed by an organization or team will provide less 
opportunities for adversaries to plan, configure, and accomplish an attack. These are also much more difficult for an adversary to evade, since they are not in 
control of the configuration or prepared for the tool.

The final grouping is also split into two levels. These groupings are focused on identifying behaviors that are associated with MITRE ATT&CK Techniques, making 
them the most difficult to evade, and providing defenders the tools to create the most robust analytics. The observables core to some implementations of a technique 
or sub-technique are associated with low-variance behaviors which are unavoidable without a substantially different implementation. Observables core to a technique or 
sub-technique are the choke points or invariant behaviors, which are unavoidable by any implementation. 

.. figure:: _static/pyramid_breakdown_pt2.png
   :alt: Breaking down the Pyramid of Pain
   :align: center

Each of these rows categorize the cost for an adversary to evade observables at each row. In addition to these analytic robustness categories, certain operations within the OS will generate events, which can be used by a defender to detect malicious activity. These are usually seen in the 
form of event IDs. However, not all event IDs are generated in the same part of the OS. Some are generated by applications, some can be called by the user, some 
are functions of the kernel, and so on. If adversaries want to bypass certain event IDs, they can just call certain API functionality lower within the OS. 

Understanding this concept can help defenders build more robust analytics, by looking at different sensor data throughout the OS. We add a second dimension to our model to reflect this second type of evasion: sensor data robustness.

.. figure:: _static/2Dmodel_07272023.PNG
   :alt: Summiting the Pyramid 2D model
   :align: center

There are three different layers within the OS in which sensor data can be generated. The application column identifies observables which are associated with the use of libraries, such as DLLs, available to defenders before adversary use. These are difficult for the adversary to modify, but can be evaded. User-mode observables are associated with user-mode OS activity, such as Sysmon process creation. Finally, kernel-mode observables are associated with kernel-mode activity occurring at ring 0. Each of these columns provide the defender a different layer to detect activity within the OS, going deeper as the columns move to the right. 

This 2D model provides the visualization of how to score the robustness of an analytic, based on the log source and the behavior associated with an attack.

Improving Analytic Robustness
-----------------------------
Let's step through an example. The below analytic looks for specific command line arguments of the ADFind tool [#f2]_, identified when Image ends with ``adfind.exe``.

.. code-block:: yaml
   
   title: Suspicious AdFind Execution
   id: 75df3b17-8bcc-4565-b89b-c9898acef911
   status: experimental
   description: Detects the execution of a AdFind for Active Directory enumeration 
   references:
      - https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx
      - https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/fin6/Emulation_Plan/Phase1.md
      - https://thedfirreport.com/2020/05/08/adfind-recon/
   author: FPT.EagleEye Team, omkar72, oscd.community
   date: 2020/09/26
   modified: 2021/05/12
   tags:
      - attack.discovery
      - attack.t1018
      - attack.t1087.002
      - attack.t1482
      - attack.t1069.002
   logsource:
      product: windows
      category: process_creation
   detection:
      selection:
         CommandLine|contains:
               - 'objectcategory'
               - 'trustdmp'
               - 'dcmodes'
               - 'dclist'
               - 'computers_pwdnotreqd'
         Image|endswith: '\adfind.exe'
      condition: selection
   falsepositives:
      - Administrative activity
   level: medium


First, we have to understand and score this analytic's event robustness category. The data source for this analytic is ``process_creation``, so it could potentially trigger Windows Event ID 4688 or Sysmon Event ID 1. 
This analytic references the Image field which does not exist in Event ID 4688, but it does exist in Sysmon Event ID 1 [#f3]_. 4688 has the field 
NewProcessName, though it could be mapped to another field name in your SIEM of choice. As a result, we assume 
the intent of this analytic is to identify command line activity in Sysmon Event ID 1s.

Sysmon Event ID 1 is generated when Win32 API functions are called to create a new process [#f4]_. Therefore it is a user-mode logsource and we can place the other observables in the U column.

.. list-table::
    :widths: 20 20 30 20
    :header-rows: 1

    * - 
      - Application (A)
      - User-mode (U)
      - Kernel-mode (K)
    * - Core to (Sub-) Technique (5)
      - 
      - EventID: 1
      - 
    * - Core to Part of (Sub-) Technique (4)
      - 
      - EventID: 1
      -
    * - Core to Pre-Existing Tool (3)
      - 
      - EventID: 1
      -
    * - Core to Adversary-brought Tool (2)
      - 
      - EventID: 1
      - 
    * - Ephemeral (1)
      - 
      - EventID: 1
      - 

Next, ``Image|endswith: '\adfind.exe'`` is placed at the **Ephemeral level**. An adversary can easily obfuscate or change the Image value by renaming 
the file. The command line arguments are placed at the **Core to Adversary-Brought Tool** level, since the command line arguments are 
specific to the ADFind tool and require modifying source code to change. Since the CommandLine and Image observables in the analytic are 
ANDed together, the net :ref:`robustness<Robustness and Boolean Logic>` is the lower of the two, resulting in a Level 1 score for the overall analytic. The entire analytic scores as a **1U**.

.. list-table::
    :widths: 20 20 30 20
    :header-rows: 1

    * - 
      - Application (A)
      - User-mode (U)
      - Kernel-mode (K)
    * - Core to (Sub-) Technique (5)
      - 
      - 
      - 
    * - Core to Part of (Sub-) Technique (4)
      - 
      -
      -
    * - Core to Pre-Existing Tool (3)
      - 
      - 
      -
    * - Core to Adversary-brought Tool (2)
      - 
      - | EventID: 1
        | CommandLine|contains:
        |   - 'objectcategory'
        |   - 'trustdmp'
        |   - 'dcmodes'
        |   - 'dclist'
        |   - 'computers_pwdnotreqd'
      - 
    * - Ephemeral
      - 
      - Image|endswith: '\\adfind.exe'
      - 

.. important:: 
   An adversary can easily evade this analytic by renaming the executable. *Can we improve this analytic so it is more robust?* Our options for increasing robustness are pivoting to a sensor that monitors kernel-level activity (moving a column to the right) or increasing the level our analytic operates at (moving up a row).

The robustness of this analytic can be increased by leveraging the OriginalFileName field in Sysmon Event ID 1 instead of Image. It is trivial 
for an adversary to change the Image name ending with ``adfind.exe`` to avoid detection. It is more challenging for an adversary to 
change the OriginalFileName, since it is derived from the PE header. Changing the PE header requires either modifying changing values at 
the executable's compile time or modifying raw bytes with a hex editor, both of which are more complex for an adversary than 
renaming a file on a compromised system.

By instead detecting ``OriginalFileName|endswith: '\adfind.exe'``, this analytic moves up a level to **2U**. However, the analytic could also be improved by dropping the AND clause and relying on the unique command line arguments.

.. list-table::
    :widths: 20 20 30 20
    :header-rows: 1

    * - 
      - Application (A)
      - User-mode (U)
      - Kernel-mode (K)
    * - Core to (Sub-) Technique (5)
      - 
      - 
      - 
    * - Core to Part of (Sub-) Technique (4)
      - 
      -
      -
    * - Core to Pre-Existing Tool (3)
      - 
      - 
      -
    * - Core to Adversary-brought Tool (2)
      - 
      - | EventID: 1
        | CommandLine|contains:
        |   - 'objectcategory'
        |   - 'trustdmp'
        |   - 'dcmodes'
        |   - 'dclist'
        |   - 'computers_pwdnotreqd'
        | OriginalFileName|endswith: '\\adfind.exe'
      - 
    * - Ephemeral
      - 
      - 
      - 

Through this process, we have improved our analytic by just changing one field to identify adversary behavior and make it more difficult for them to evade detection 
of this analytic. Not everyone is going to be able to collect Sysmon data or implement all analytic improvements. However, it gets us thinking of where and how to make small, incremental steps within our environment and increase the robustness of analytics.

Assumptions and Caveats
-----------------------
* Our current guidance addresses sensors and levels within Windows systems. There is definitely room to create guidance for networks, cloud, virtual machines, and other platform types to improve analytics across various platforms. We will attempt to develop guidance for these other platforms in :ref:`future work<Future-Work>`.
* The levels and observables currently defined by Summiting the Pyramid address the robustness of analytics, compared to precision and recall. :ref:`Read more about precision, recall, and robustness here <Robustness Precision Recall>`.
* One way adversaries evade detection is by tampering with the defensive sensor(s). That approach is out of scope for this project, and we focus solely on analytics that are robust, assuming the data they use has not been tampered with. Detecting tampering is left to other defensive and detection measures.
* Tools and techniques will change over time, meaning the analytic score might change as will. This goes for updates of the OS, pre-existing tools, and new adversary tool functionality, not just at levels 4 and 5.
* Analytics towards the higher levels of the 2D model will be more difficult to produce than those which are lower in the model. This is due to the level of research required for defenders in determining if certain observables cover some or all of a technique. For defenders, a balance between the cost needed to research low variance and invariant behaviors of techniques and the robustness of analytics will be needed.
* This 2D model for the Summiting methodology opens opportunity for adding additional dimensions for creating more robust and potentially more precise analytics. This can include factors such as timing, efficiency, and additional implementations. As the model continues to evolve, :ref:`the focus on additional dimensions may be explored in <Future-Work>`.

We are always looking for feedback and integrating your thoughts and ideas! Open a `GitHub issue here <https://github.com/center-for-threat-informed-defense/summiting-the-pyramid/issues>`_ to share your ideas, feedback, and scored analytics.

.. rubric:: References

.. [#f1] http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
.. [#f2] https://github.com/SigmaHQ/sigma/blob/30bee7204cc1b98a47635ed8e52f44fdf776c602/rules/windows/process_creation/win_susp_adfind.yml
.. [#f3] https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001
.. [#f4] https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
