:orphan:

----------
BloodHound
----------

https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_bloodhound_collection.yml

.. list-table::
    :widths: 30 70

    * - Original Analytic
      - | selection_1:
        | TargetFilename|endswith:
        |   - '_BloodHound.zip'
        |   - '_computers.json'
        |   - '_containers.json'
        |   - '_domains.json'
        |   - '_gpos.json'
        |   - '_groups.json'
        |   - '_ous.json'
        |   - '_users.json'
        | selection_2:
        | TargetFilename|contains|all:
        |   - 'BloodHound'
        |   - '.zip'
    * - Improved Analytic
      - | | rex field=target_file_name ".*\\\\(?<bloodhound_format>\d{14}_.*\.zip)"?
        | | where isnotnull(bloodhound_format)

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
      - 
    * - Operational/Environmental Variables
      - | | rex field=target_file_name ".*\\\\(?<bloodhound_format>\d{14}_.*\.zip)"?
        | | where isnotnull(bloodhound_format)

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
..
    TODO: verify the level of this analytic.

Looking at specific file names is very brittle. Looking for the file format using regex is 
still at the Operational/Environmental Variable level, however, it is significantly more robust then 
the specific filename seen in the SIGMA rule.
