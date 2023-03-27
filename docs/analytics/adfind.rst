------
ADFind
------

Original Analytic: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_delete/registry_delete_removal_amsi_registry_key.yml

Original Analytic Scoring
^^^^^^^^^^^^^^^^^^^^^^^^^
.. list-table::
    :widths: 30 70
    :header-rows: 1

    * - Level
      - Observables
    * - Kernel/Interfaces
      - 
    * - System Calls
      - 
    * - OS API
      - 
    * - Library API
      - 
    * - Native Tooling
      - 
    * - Custom Software/Open Source
      - | CommandLine|contains:
        |   - 'objectcategory'
        |   - 'trustdmp'
        |   - 'dcmodes'
        |   - 'dclist'
        |   - 'computers_pwdnotreqd'
    * - Operational/Environmental Variables
      - Image|endswith: ‘\adfind.exe’

Improved Analytic Scoring
^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
    :widths: 30 70
    :header-rows: 1

    * - Level
      - Observables
    * - Kernel/Interfaces
      - 
    * - System Calls
      - 
    * - OS API
      - 
    * - Library API
      - 
    * - Native Tooling
      - 
    * - Custom Software/Open Source
      - | CommandLine|contains:
        |   - 'objectcategory'
        |   - 'trustdmp'
        |   - 'dcmodes'
        |   - 'dclist'
        |   - 'computers_pwdnotreqd'
        | OriginalFileName: ‘adfind.exe’
    * - Operational/Environmental Variables
      - 

Research Notes and Caveats
^^^^^^^^^^^^^^^^^^^^^^^^^^
We are given this analytic that looks for specific command line arguments dealing with the ADFind tool. 
It also looks for ``adfind.exe`` in the ``image`` file path. Looking at the current data sources 
provided by the analytic and the Pyramid of Evasiveness, we can begin to place where everything is. 
First, we place ``Image|endswith: ‘\adfind.exe’`` within the Operational and Environmental Variables level. 
While the intention of this analytic is looking for the execution of commands through this tool, this 
image path can be obfuscated by adversaries within the command line. We put the command line arguments into the 
Custom Software and Open Source level, since these command line arguments are specific to the tool itself. 
The final placement of the analytic is below.

.. important:: This analytic can be evaded by adversaries if they rename the binary. 
    Can we improve this analytic so it is more robust in terms of the tools that could be used to evade it? 
    We cannot always improve an analytic to the system application or kernel level, but we can make smaller improvements.

Adversaries can change the ``image`` name to evade some analytics. 
However, they must declare the tool they are using somewhere--in many cases this is at compile time. This declaration can usually be 
identified in Sysmon's ``OriginalFileName`` field.