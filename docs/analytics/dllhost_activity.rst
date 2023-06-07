:orphan:

----------------------------
Suspicious DLL Host Activity
----------------------------

..
    Insert link to analytic here (like a Sigma rule)

https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_dllhost_no_cli_execution.yml

.. list-table::
    :widths: 30 70

    * - Original Analytic
      - command="dllhost.exe" ImageFileName="\\dllhost.exe"
    * - Improved Analytic
      - ImageFileName="\*\\dllhost.exe" (parent_file_name="scrons.exe" OR lsass OR command="\*dllhost.exe")

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
      - Tools Outside Adversary Control
      - ImageFileName="\\dllhost.exe"
    * - 2
      - Tools Within Adversary Control
      - 
    * - 1
      - Operational/Environmental Variables
      -  command="dllhost.exe"
      
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
      - Tools Outside Adversary Control
      - 
    * - 2
      - Tools Within Adversary Control
      - ImageFileName="\*\\dllhost.exe" (parent_file_name="scrons.exe" OR lsass OR command="\*dllhost.exe")
    * - 1
      - Operational/Environmental Variables
      - 

Research Notes and Caveats
^^^^^^^^^^^^^^^^^^^^^^^^^^

This activity has many IOCs that individually don’t have much context but when put together leverage Native 
Windows tools behavior to detect the DLLHost activity. This also makes use of a keyword search that is very 
challenging to score as it can be found in any field and still detect the activity. The way I scored this 
was with the expected fields it would be found in. Also with the OR logic I was able to link together lower 
level detection with lower level detection and together they still provide more robust detection capabilities.
