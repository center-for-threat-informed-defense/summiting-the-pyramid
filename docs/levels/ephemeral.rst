.. _Ephemeral Values:

Level 1: Ephemeral
==================

**Description:** Observables that describe a specific instance of activity but
not durable behavior. These values are easy for an adversary to change without
materially affecting the attack.

Ephemeral observables capture characteristics of what is happening at a
particular point in time, such as a filename, hash, process ID, domain name, or
other value associated with a specific execution. These observables can be highly useful for identifying known malicious
activity. However, they generally provide limited resistance to adversary
evasion because changing the observable does not require the adversary to
meaningfully change the underlying behavior.


Why are these observables placed at Level 1?
--------------------------------------------

Level 1 observables are either directly controlled by the adversary or can
change between executions without changing the underlying attack. For example, changing a single bit in a file produces a different hash, a file
can be renamed without changing its functionality, and a process receives a
different process ID each time it executes. To evade a detection based on a Level 1 observable, an adversary generally
needs only to **change a simple value or rerun the attack differently**. Because these observables describe a particular instance of activity rather
than durable behavior, detections that rely exclusively on them may not detect
the same behavior when the adversary changes incidental details.


Examples
--------

Examples of Level 1 observables include:

* Hash values
* Attacker-controlled filenames
* Attacker-controlled domain names and IP addresses
* Process IDs and process-instance identifiers
* Attacker-selected pipe names
* Configurable ports
* Other transient or attacker-selected values


Observables
-----------

The examples below illustrate common Level 1 observables and how they may
change or be modified to evade detection.

.. list-table::
   :header-rows: 1
   :widths: 22 25 33 20

   * - Category
     - Observable
     - Generating Activity
     - Evade Behavior

   * - Hash Values
     - ``Hashes`` (Sysmon)
     - A hash identifies the contents of a particular file or object.
     - Modify the file and generate a new hash.

   * - IP Addresses
     - ``SourceIp`` (Sysmon), ``DestinationIp`` (Sysmon)
     - An address identifies a network endpoint used during a particular
       instance of activity.
     - Use a different address, host, proxy, VPN, or infrastructure.

   * - Protocol-Specific or Configurable Ports
     - ``SourcePort`` (Sysmon), ``DestinationPort`` (Sysmon)
     - A port identifies the network endpoint used for a connection.
     - Change the port when the implementation or protocol permits it.

   * - Filenames
     - ``Image`` (Sysmon), ``ParentImage`` (Sysmon),
       ``TargetFilename`` (Sysmon)
     - A filename identifies a particular file, image, or executable involved
       in the activity.
     - Rename the file or deploy it under another name.

   * - Domain Names
     - ``SourceHostname`` (Sysmon), ``DestinationHostname`` (Sysmon)
     - A domain or hostname identifies infrastructure used during the activity.
     - Use different infrastructure or change the associated domain name.

   * - Process-Instance Metadata
     - ``ProcessGuid`` (Sysmon), ``ProcessId`` (Sysmon),
       ``ParentProcessGuid`` (Sysmon)
     - The operating system assigns identifiers to individual process
       instances.
     - Rerun the activity, causing new process-instance values to be generated.

   * - Pipe Names
     - ``PipeName`` (Sysmon)
     - A pipe creator may select a name when creating a named pipe.
     - Use a different pipe name when the name is controlled by the
       implementation.


Classification Depends on Context
---------------------------------

An observable type is not inherently assigned to a single Summiting level.
Its classification depends on why the observable exists and what the
adversary must change to avoid it. For example, an attacker-selected filename or pipe name may be ephemeral.
However, a filename, pipe name, or other value that is imposed by a required
system interaction may be system-constrained or even shared across multiple
implementations. Similarly, a port is Level 1 only when the adversary can freely change it
without materially changing the behavior. A port required by a protocol or
system interaction should be evaluated according to that constraint rather
than automatically classified as ephemeral. When scoring an observable, consider the relationship between the observable
and the behavior being detected—not simply the field or data type in which it
appears.


.. rubric:: References

.. [#f1] http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
.. [#f2] https://usa.kaspersky.com/resource-center/definitions/what-is-an-ip-address
.. [#f3] https://www.cloudflare.com/learning/network-layer/what-is-a-computer-port/
.. [#f4] https://www.codecademy.com/resources/blog/what-is-a-domain-name/#domain-name-registrars-and-registries
.. [#f5] https://www.tutorialspoint.com/inter_process_communication/inter_process_communication_process_creation_termination.htm
.. [#f6] https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names
