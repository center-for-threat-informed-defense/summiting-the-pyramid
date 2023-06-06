.. _AD Find:

-----------------
Suspicious ADFind
-----------------

https://github.com/SigmaHQ/sigma/blob/30bee7204cc1b98a47635ed8e52f44fdf776c602/rules/windows/process_creation/win_susp_adfind.yml

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
    * - Improved Analytic
      - | CommandLine|contains:
        |   - 'objectcategory'
        |   - 'trustdmp'
        |   - 'dcmodes'
        |   - 'dclist'
        |   - 'computers_pwdnotreqd'
        | OriginalFileName: 'adfind.exe'

Original Analytic Scoring
^^^^^^^^^^^^^^^^^^^^^^^^^
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
      - Artifacts Outside Adversary Control
      - 
    * - 2
      - Artifacts Within Adversary Control
      - | CommandLine|contains:
        |   - 'objectcategory'
        |   - 'trustdmp'
        |   - 'dcmodes'
        |   - 'dclist'
        |   - 'computers_pwdnotreqd'
    * - 1
      - Operational/Environmental Variables
      - Image|endswith: '\\adfind.exe'

Improved Analytic Scoring
^^^^^^^^^^^^^^^^^^^^^^^^^

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
      - Artifacts Outside Adversary Control
      - 
    * - 2
      - Artifacts Within Adversary Control
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

Research Notes and Caveats
^^^^^^^^^^^^^^^^^^^^^^^^^^
We are given this analytic that looks for specific command line arguments dealing with the ADFind tool. 
It also looks for ``adfind.exe`` in the ``image`` file path. Looking at the current data sources 
provided by the analytic and the Pyramid of Evasiveness, we can begin to place where everything is. 
First, we place ``Image|endswith: '\adfind.exe'`` within the Operational and Environmental Variables level. 
While the intention of this analytic is looking for the execution of commands through this tool, this 
image path can be obfuscated by adversaries within the command line. We put the command line arguments into the 
Tools Within Adversary Control level, since these command line arguments are specific to the tool itself. 
The final placement of the analytic is below.

.. important:: This analytic can be evaded by adversaries if they rename the binary. 
    Can we improve this analytic so it is more robust in terms of the tools that could be used to evade it? 
    We cannot always improve an analytic to the system application or kernel level, but we can make smaller improvements.

Adversaries can change the ``image`` name to evade some analytics. 
However, they must declare the tool they are using somewhere--in many cases this is at compile time. This declaration can usually be 
identified in Sysmon's ``OriginalFileName`` field.