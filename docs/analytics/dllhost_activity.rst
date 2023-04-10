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
      - ImageFileName="\\dllhost.exe"
    * - Custom Software/Open Source
      - 
    * - Operational/Environmental Variables
      -  command="dllhost.exe"
      
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
      - ImageFileName="\*\\dllhost.exe" (parent_file_name="scrons.exe" OR lsass OR command="\*dllhost.exe")
    * - Operational/Environmental Variables
      - 

Research Notes and Caveats
^^^^^^^^^^^^^^^^^^^^^^^^^^

This activity has many IOCs that individually don’t have much context but when put together leverage Native 
Windows tools behavior to detect the DLLHost activity. This also makes use of a keyword search that is very 
challenging to score as it can be found in any field and still detect the activity. The way I scored this 
was with the expected fields it would be found in. Also with the OR logic I was able to link together lower 
level detection with lower level detection and together they still provide more robust detection capabilities.
