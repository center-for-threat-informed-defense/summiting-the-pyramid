-------------------------------------------
Service Registry Permissions Weakness Check
-------------------------------------------

- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_get_acl_service.yml

.. list-table::
    :widths: 30 70

    * - Original Analytic
      - | ScriptBlockText|contains|all:
        |   - 'get-acl'
        |   - 'REGISTRY: HKLM\\SYSTEM\\CurrentControlSet\\Services\\'
    * - Improved Analytic
      - | EventID: 4663
        | TargetObject: \“\*SYSTEM\\CurrentControlSet\\Services\\\*\”

Access: READ_CONTROL

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
      - 
    * - 2
      - Tools Within Adversary Control
      - | ScriptBlockText|contains|all:
        |   - 'get-acl'
        |   - 'REGISTRY: HKLM\\SYSTEM\\CurrentControlSet\\Services\\'
    * - 1
      - Operational/Environmental Variables
      - 

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
      - | EventID: 4663
        | TargetObject: \“\*SYSTEM\\CurrentControlSet\\Services\\\*\”
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
      - 
    * - 1
      - Operational/Environmental Variables
      - 

Research Notes and Caveats
^^^^^^^^^^^^^^^^^^^^^^^^^^
The analytic starts out using the ETW Event ID 4104, filtering off the ScriptBlockText field. This is looking at the text within the script to determine what it is doing. 
In our research PowerShell scripts are relatively easy to change or obfuscate key words. For example, the cmdlet ``get-acl`` is predefined, but the same action can be done 
with a custom cmdlet that is named something different. This method would completely hide the ``get-acl`` name from the script text. The registry name can also be broken 
up or obfuscated in simple ways to avoid this type of logging.  

Setting a Security Access Control List (SACL) on the registry key allows us to use a kernel mode data source for the same operation. This logs what the script is 
trying to accomplish without looking at the script itself, this takes the control from the adversary to the defender. SACLs have many options when configuring them 
and this requires the ``Read Control`` value to be set. This triggers any time the keys permissions are triggered. However, this is a precision measure as you could 
just log the ``Full Control`` set of activity and get more of an idea of what the key is being used for, then query within those results for the ``Access = READ_CONTROL`` 
logs. 

However you set the SACL you are switching from detecting the tools the adversary are using to do something and instead detecting on the goal of the operation 
with a log source that is monitoring from within the kernel.
