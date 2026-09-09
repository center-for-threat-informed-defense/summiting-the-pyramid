.. _Pre-Existing Tools:

Level 3: System-Constrained Interaction
=======================================

**Description:** Observables associated with interactions the adversary must
perform with the target system or environment and cannot freely change at the
point of execution.

Level 3 observables are constrained by the system, application, account,
target, protocol, or environment with which the adversary must interact.
Unlike ephemeral or implementation-specific values, these observables are not
entirely determined by the adversary's tooling or configuration choices. These constraints make the observable more difficult to change without also
changing how or where the adversary performs the operation.


Why are these observables placed at Level 3?
--------------------------------------------

At Levels 1 and 2, an adversary can generally evade a detection by changing an
incidental value or reconfiguring the implementation. At Level 3, the observable is imposed or constrained by something outside the
adversary's immediate control at the point of interaction. The adversary must
operate within the functionality, permissions, interfaces, protocols, or
resources exposed by the target environment. To evade a Level 3 observable, the adversary generally must **change the
operational approach or interact with a different target**, rather than simply
modify a value or reconfigure their tooling.


System Constraints and Pre-Existing Functionality
--------------------------------------------------

Pre-existing tools and native system functionality are common sources of
Level 3 observables because the adversary typically does not control how that
functionality is implemented. An adversary using PowerShell, a Windows service, an authentication service, or
another pre-existing capability must operate within the interfaces and
constraints exposed by that functionality. While the adversary may control how
they invoke the capability, they may not be able to freely change the
system-generated or target-dependent interactions that result. This is also why some Living off the Land activity can produce useful Level 3
observables. The adversary may choose to use legitimate functionality, but
doing so can require interactions determined by the environment rather than by
the adversary's tooling.


Inside-Boundary Interactions
----------------------------

Network interactions can also become system-constrained when the adversary
does not control both sides of the interaction. For example, if an adversary initiates lateral movement or remote execution
from a compromised endpoint toward another internal system that they do not
yet control, the target system constrains how the adversary can interact with
it. The adversary must use the protocols, services, authentication mechanisms,
and applications available on that target. Observables generated on the responder or target side can therefore provide
greater robustness than characteristics of a connection for which the
adversary controls both endpoints. The important distinction is not simply whether traffic crosses an
organizational boundary. It is **how much control the adversary has over the
interaction being observed**.


Examples
--------

Examples of Level 3 observables may include:

* Target resources or system objects that the adversary must interact with
* System-assigned or system-constrained values
* Authentication and session properties imposed by the target environment
* Access or privilege context required for an operation
* Interactions with pre-existing functionality that the adversary cannot
  freely modify
* Responder-side observations of network interactions where the adversary
  does not control the target


Observables
-----------

The examples below illustrate types of observables that may represent
system-constrained interactions.

.. list-table::
   :header-rows: 1
   :widths: 22 28 30 20

   * - Category
     - Observable
     - System Constraint
     - Evade Behavior

   * - Target Resource
     - ``TargetImage`` or other required target object
     - The operation requires interaction with a particular system resource or
       target that the adversary cannot freely rename or modify at the point
       of execution.
     - Change the target or use a different operational approach.

   * - Authentication
     - Authentication method, service, or decision information
     - The target environment determines which authentication mechanisms and
       access requirements are available.
     - Use a different authentication path, identity, or target.

   * - User Session
     - Logon type or session characteristics
     - Session properties may be determined by the access mechanism and target
       environment.
     - Change the access method or operational approach.

   * - Access / Privilege Context
     - Integrity level, token elevation, access level, or similar
       system-derived context
     - The system assigns or enforces the access context required for the
       interaction.
     - Obtain different privileges or use an alternative method.

   * - Network Interaction
     - Responder-side protocol, service, endpoint, or connection information
     - A target not controlled by the adversary constrains the protocols,
       services, and interfaces available for interaction.
     - Interact with a different target or use another operational approach.

   * - Pre-Existing Functionality
     - System- or application-constrained behavior associated with native
       functionality
     - The adversary can invoke the functionality but cannot freely change how
       the target system implements it.
     - Use different functionality or change the operational approach.


The Same Field Can Appear at Different Levels
---------------------------------------------

The field containing an observable does not determine its robustness level by
itself. The classification depends on the relationship between the observable
and the behavior. For example, an ``Image`` value selected by an adversary may be Level 1 because
the executable can simply be renamed. A ``TargetImage`` value may be Level 3
when the operation requires interaction with a particular system process or
resource that the adversary cannot change at the point of execution. The same principle applies to command-line arguments, filenames, pipe names,
network values, and other observable types. An attacker-selected value may be
ephemeral or implementation-controlled, while a similar value imposed by the
target system may be system-constrained.

When assigning a Summiting level, ask:

**What would the adversary actually have to change to prevent this observable
from occurring?**

If the answer is that they must change their operational approach, interact
with a different target, or otherwise work around a system or environmental
constraint, the observable may belong at Level 3.



.. rubric:: References [#f1]_ [#f2]_ [#f3]_ [#f4]_ [#f5]_ 

.. [#f1] https://darktrace.com/blog/living-off-the-land-how-hackers-blend-into-your-environment
.. [#f2] https://www.gdatasoftware.com/blog/2022/02/37248-living-off-the-land
.. [#f3] https://csrc.nist.gov/glossary/term/tool_configuration
.. [#f4] https://auth0.com/docs/manage-users/sessions
.. [#f5] https://www.ultimatewindowssecurity.com/securitylog/book/page.aspx?spid=chapter3
