.. _AD Find:

-----------------
Suspicious ADFind
-----------------

- https://github.com/SigmaHQ/sigma/blob/30bee7204cc1b98a47635ed8e52f44fdf776c602/rules/windows/process_creation/win_susp_adfind.yml

Original Analytic Scoring
^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
    :widths: 20 20 30 20
    :header-rows: 1

    * - 
      - Library
      - User-mode
      - Kernel-mode
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

Improved Analytic Scoring
^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
    :widths: 20 20 30 20
    :header-rows: 1

    * - 
      - Library
      - User-mode
      - Kernel-mode
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

This analytic looks for specific command line arguments of the ADFind tool. ADFind is identified when Image ends with ``adfind.exe``. 
The logsource for this analytic is process create, so it could potentially fire for Event IDs 4688 and/or Sysmon Event ID 1, but 
we can infer because of the the Image field in the analytic that it is detecting instances of Sysmon Event ID 1. 4688 has the field 
NewProcessName, though it could be mapped to another name in your SIEM of choice. However, for scoring this analytic we will assume 
the intention was to identify command line activity in Sysmon Event ID 1s.

Sysmon Event ID 1 is generated when Win32 API functions are called to create a new process. Therefore it is a user-mode observable 
and we can place other observables in the U column. 

First, ``Image|endswith: '\adfind.exe'`` is placed at the **Ephemeral level**. An adversary can easily change the Image value by renaming 
the file. The command line arguments are placed at the **Core to Adversary-Brought Tool** level, since the command line arguments are 
specific to ADFind tool and require modifying source code to change. Since the CommandLine and Image parts of the analytic are 
ANDed together, according to our Boolean logic, the entire analytic scores as a 1U.

This analytic can be made more robust by leveraging the OriginalFileName field in Sysmon Event ID 1 instead of Image. It is trivial 
for an adversary to change the Image name ending with ``adfind.exe`` to avoid detection. It is more challenging for an adversary to 
change the OriginalFileName, since it is derived from the PE header. Changing the PE header requires either modifying values at 
the executable's compile time or modifying raw bytes with a hex editor, both of which are more complex for an adversary than 
renaming a file on a compromised system.

By instead detecting ``OriginalFileName|endswith: '\adfind.exe'``, this analytic moves up a level to 2U.