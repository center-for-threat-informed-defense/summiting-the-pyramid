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
      - 
    * - 1
      - Operational/Environmental Variables
      - | | rex field=target_file_name ".*\\\\(?<bloodhound_format>\d{14}_.*\.zip)"?
        | | where isnotnull(bloodhound_format)

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
        | OriginalFileName: ‘adfind.exe’
    * - 1
      - Operational/Environmental Variables
      - 

Research Notes and Caveats
^^^^^^^^^^^^^^^^^^^^^^^^^^
..
    TODO: verify the level of this analytic.

Looking at specific file names is very brittle. Looking for the file format using regex is 
still at the Operational/Environmental Variable level, however, it is significantly more robust then 
the specific filename seen in the SIGMA rule.
