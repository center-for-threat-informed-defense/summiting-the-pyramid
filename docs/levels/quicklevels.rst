Levels and Observables
======================

.. list-table:: Difficulty of Bypassing Analytic Observables
   :widths: 15 25 25 50 25
   :header-rows: 1

   * - Level
     - Level Name
     - Observable Examples
     - Observable Fields
     - Observable Values
   * - 7
     - Kernel
     - 
     - add (CAR), remove (CAR), key_edit (CAR), value_edit (CAR)
     - Event ID 4688, Event ID 4689, Sysmon ID 8
   * - 6
     - System Calls
     - File manipulation, communication protection
     - 
     - Sysmon ID 10
   * - 5
     - OS API
     - API Calls
     - create (CAR)
     - Sysmon ID 1, Sysmon ID 5
   * - 4
     - Library API
     - e.g., .NET Framework, DLLs, COM methods
     - 
     - .NET (Wndows)
   * - 3
     - Tools Outside Adversary Control
     - Signatures, command-line arguments, tool-specific configurations, user session, authentication
     - signer (CAR), signature_valid (CAR), mime_type (CAR), link_target (CAR), command line (Sysmon), parent command line (Sysmon), process command line (Windows EID), command_line (CAR), parent_comand_line (CAR), integrity level (Sysmon), mandatory label (Windows EID), token elevation type (Windows EID), original file name (Sysmon), access_level (CAR), integrity_level (CAR), login_type (CAR), login_successful (CAR), auth_service (CAR), decision_reason (CAR), method (CAR)
     - 
   * - 2
     - Tools Within Adversary Control
     - Signatures, command-line arguments, tool-specific configurations, metadata, binaries
     - Command line (Sysmon), integrity level (Sysmon), parent command line (Sysmon)
     - 
   * - 1
     - Operational and Environmental Variables
     - Hash values, IP addresses, protocol-specific ports, file names, domain names, processes, user oriented observables, others
     - Hashes (Sysmon), md5_hash (CAR), sha1_hash (CAR), sha256_hash (CAR), target_address (CAR), dest_ip (CAR), src_ip (CAR), dest_port (CAR), src_port (CAR), image (Sysmon), parent image (Sysmon), current directory (Sysmon), extension (CAR), file_name (CAR), file_path (CAR), image_path (CAR), current_working_directory (CAR), exe (CAR), parent_exe (CAR), app_name (CAR), auth_target (CAR), fqdn (CAR), ad_domain (CAR), target_ad_domain (CAR), process GUID (Sysmon), process ID (Sysmon), parent process GUID (Sysmon), parent process ID (Sysmon), Subject SID (Windows), target SID (Windows EID), new process ID (Windows EID), creator process ID (Windows EID), pid (CAR), ppid (CAR), user (Sysmon), logon GUID (Sysmon), logon ID (Sysmon), subject name (Windows EID), subject domain (Windows EID), subject logon ID (Windows EID), target domain (Windows EID), target logon ID (Windows EID), new process name (Windows EID), creator process name (Windows EID), gid (CAR), group (CAR), owner_uid (CAR), owner (CAR), user (CAR), uid (CAR), guid (CAR), hostname (CAR), target_guid (CAR), target_uid (CAR), target_user (CAR), target_user_role (CAR), target_user_type (CAR), target_name (CAR), target_pid (CAR), login_id (CAR), user_agent (CAR), user_role (CAR), contents (CAR), creation_time (CAR), mode (CAR), previous_creation_time (CAR), env_vars (CAR), data (CAR), new_content (CAR), value (CAR), response_time
     - 

