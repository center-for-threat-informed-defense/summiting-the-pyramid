.. _Pre-Existing Tools:

------------------------------------------------------
Level 3: Core to Pre-Existing Tools or Inside Boundary
------------------------------------------------------

**Description**: Observables associated with a tool or functionality that
existed on the system pre-compromise, may be managed by the defending
organization, and is difficult for an adversary to modify.

**Why are tools split between adversary-brought and pre-existing?**

Pre-existing tools provide less flexibility to adversaries than tools that are
brought by an adversary, as an adversary must behave and act with what is
available to them through the tool. The configurations, command-line arguments,
and other observables for this level will remain consistent with what is
available for the tool.

Since the adversary cannot change the capability because it is managed by an
organization, it is much more difficult to distinguish adversary use from benign
use. This provides an opportunity for an adversary to blend into the computing
environment, also known as a Living off the Land (LotL) attack [#f1]_ [#f2]_.
It is likely that analytics utilizing native tool observables will need to be
combined with other observables at other levels or require further research into
low-variance behaviors of abusing these tools through MITRE ATT&CK techniques.

**Why are detections between the inside and outside boundaries split?**

Detections are split between the inside and outside boundaries because the
analytic robustness is greatly dependent on whether the adversary controls one
or both endpoints in a network connection. For example, given a network
connection that extends outside the defender's boundary, such as to an endpoint
somewhere on the public internet, we presume that the adversary has control over
both the external endpoint and the internal, compromised endpoint. If the
adversary has control of both endpoints, then they have the advantage and the
flexibility to configure the tool or network connection, such as encryption,
obfuscation, and so on, and change implementations to meet their specific needs,
which lowers the analytic robustness to Level 2: Core to Adversary-Brought Tool
or Outside Boundary.

On the other hand, if a network connection stays inside the defender's boundary,
then the analytic robustness depends on the ATT&CK tactic or phase of the
adversary's cyber operation. If the network connection is for the purpose of
lateral movement or remote execution, then the adversary controls only the
originator endpoint and has not yet achieved control of the target endpoint. The
analytic robustness would improve to Level 3: Core to Pre-Existing Tools or
Inside Boundary because the adversary must behave and act with what is available
to them through network protocols, operating systems, and applications running
on the target endpoint.

**What is the difference between Ephemeral observables and Core to Pre-Existing
Tool observables?**

Some observables that may seem to have Level 1 (Ephemeral) properties may be
classified as Level 3 (Core to Pre-Existing Tools or Inside Boundary) if they
meet certain conditions, notably if they are key to the operation of the attack
and not able to be modified at that point in the attack chain.  For example,
while an “Image” is an Ephemeral observable, a “TargetImage” value can be deemed
Core to Pre-Existing Tools when it is a key component of the program's function
and at the point where it is being detected (e.g., in Sysmon EID 10), and thus
it is not directly accessible for change by the adversary. To evade detection
would require the adversary to have already accessed and modified the value.
Additionally, a Level 1 value can move up to a Level 3 value if the value itself
is critical for the functioning of the program. For example, a specific
filename, including a file path, that is in the environment would be considered
a Level 3.

**Examples**: Signatures, command-line arguments, tool-specific configurations,
metadata, binaries

.. note::

    These observables may change as pre-existing tools present in the environment change.

Observables
^^^^^^^^^^^
+-------------------------------+-----------------------------------+------------------------------+--------------------------------+
| Category                      | Observables                       | Generating Activity          |  Evade Behavior                |
+===============================+===================================+==============================+================================+
| Command-Line Arguments        |  | CommandLine (Sysmon)           | Built into the tool to       | Change the tool or             |
|                               |  | Process Command Line (EID)     | identify different           | configuration that has         |
|                               |  | ParentCommandLine (Sysmon)     | functionalities, be called   | different command-line         |
|                               |                                   | by a tool or scripts, or be  | arguments.                     |
|                               |                                   | called by an interactive     |                                |
|                               |                                   | sessions with a user.        |                                |
|                               |                                   |                              |                                |
+-------------------------------+-----------------------------------+------------------------------+--------------------------------+
| Process Creation              |  | OriginalFileName (Sysmon)      | Filename is embedded into the| Use a tool with a different    |
|                               |                                   | PE header of a tool.         | filename or edit the PE header |
+-------------------------------+-----------------------------------+------------------------------+--------------------------------+
| Signatures                    |  | Signature (Sysmon)             |                              |                                |
|                               |  | SignatureStatus (Sysmon)       |                              |                                |
|                               |  | link_target (Sysmon)           |                              |                                |
+-------------------------------+-----------------------------------+------------------------------+--------------------------------+
| Tool-Specific Configurations  |  | Integrity Level (Sysmon)       | A recommendation for setting | Pivot to tool or raise         |
|                               |  | Mandatory Label (EID)          | up and using tools that      | permissions to avoid alerts    |
|                               |  | Token Elevation Type (EID)     | support processing of        | on a specific-configuration.   |
|                               |  | Access Level (EID)             | information. [#f3]_          |                                |
|                               |  | File Path Outside Adversary    |                              |                                |
|                               |   Control                         |                              |                                |
+-------------------------------+-----------------------------------+------------------------------+--------------------------------+
| User Session                  |  | Login Type (EID)               | A user log ons to a profile  | Log in to application or user  |
|                               |  | Login successful (EID)         | or application [#f4]_        | with a different logon type    |
|                               |                                   |                              | [#f5]_                         |
+-------------------------------+-----------------------------------+------------------------------+--------------------------------+
| Authentication                |  | Auth Service (CAR)             |                              |                                |
|                               |  | Decision Reason (CAR)          |                              |                                |
|                               |  | Method (CAR)                   |                              |                                |
+-------------------------------+-----------------------------------+------------------------------+--------------------------------+
| Network Connection            |  | Originator IP Address          | The adversary initiates an   | For Inside Boundary, if the    |
|                               |  | Responder IP Address           | activity on the originator   | adversary controls only the    |
|                               |  | TCP/UDP Ports                  | endpoint that results in a   | originator endpoint and not the| 
|                               |  | Inbound/Outbound               | network connection to another| responder endpoint, then this  |
|                               |  | Process Name                   | endpoint.                    | observable would not be        |
|                               |  | Process ID                     |                              | evadable when observed on the  |
|                               |  | User Account                   |                              | responder endpoint.            |
+-------------------------------+-----------------------------------+------------------------------+--------------------------------+
| Named Pipe Connection         |  | Pipe Name                      | The adversary initiates an   | For Inside Boundary, if the    |
|                               |  | Originator IP Address          | activity on the originator   | adversary controls only the    |
|                               |  | Originator Port                | endpoint that results in a   | originator endpoint and not the| 
|                               |  | Process Name                   | network connection to a named| responder endpoint, then this  | 
|                               |  | Process ID                     | pipe on another endpoint.    | observable would not be        |
|                               |  | User Account                   |                              | evadable when observed on the  |
|                               |  | User Account                   |                              | responder endpoint.            |
+-------------------------------+-----------------------------------+------------------------------+--------------------------------+

.. rubric:: References

.. [#f1] https://darktrace.com/blog/living-off-the-land-how-hackers-blend-into-your-environment
.. [#f2] https://www.gdatasoftware.com/blog/2022/02/37248-living-off-the-land
.. [#f3] https://csrc.nist.gov/glossary/term/tool_configuration
.. [#f4] https://auth0.com/docs/manage-users/sessions
.. [#f5] https://www.ultimatewindowssecurity.com/securitylog/book/page.aspx?spid=chapter3
