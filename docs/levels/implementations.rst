.. _Some Implementations:

Level 4: Low-Variance Behaviors / Core Sometimes
=================================================

**Description:** Observables associated with low-variance behaviors that are
core to some implementations of a technique or sub-technique and are
unavoidable without using a substantially different implementation.

Level 4 observables represent behaviors that recur across multiple ways of
performing a technique. They are not necessarily required by every
implementation, but when an adversary chooses an implementation that relies on
the behavior, the observable is difficult to avoid without changing the
implementation strategy. Identifying these low-variance behaviors can provide robust detection
opportunities across multiple implementations of a technique.


Why are these observables placed at Level 4?
--------------------------------------------

An adversary may be able to evade a Level 4 observable by choosing a different
implementation of the technique. However, doing so requires more than
reconfiguring a tool or changing an incidental value. The adversary must instead change the **implementation strategy** used to
accomplish the behavior. Level 4 therefore represents observables that are core to some implementations
of a technique or sub-technique, while Level 5 observables represent behaviors
that are invariant across all known implementations.


Observables
-----------

The examples below illustrate low-variance behaviors that are core to some
implementations.

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Technique / Sub-Technique
     - Observable
     - Low-Variance Behavior

   * - Modify Authentication Process (T1556)
     - ``AttributeLDAPDisplayName: msDS-KeyCredentialLink``
     - ``msDS-KeyCredentialLink`` is a system-recognized attribute used by
       the authentication infrastructure and is required by implementations
       that use this mechanism.

   * - OS Credential Dumping: LSASS Memory (T1003.001)
     - ``TargetImage = lsass.exe`` and
       ``GrantedAccess = 0x1010`` or ``0x1410``
     - Access to ``lsass.exe`` using these access patterns is characteristic
       of some implementations of LSASS memory access. Other access masks and
       implementations may also be possible.

   * - Scheduled Task/Job: At (T1053.002) - Remote
     - Event 5145: ``Relative Target Name = atsvc``;
       Sysmon Event 18: ``PipeName = atsvc``
     - Remote use of the Windows At Service through the ``atsvc`` named pipe
       is characteristic of implementations using this mechanism.

   * - Modify Registry (T1112) - Remote
     - Event 5145: ``Relative Target Name = winreg``;
       Sysmon Event 18: ``PipeName = winreg``
     - Remote Registry access through the ``winreg`` mechanism is characteristic
       of implementations that use this interface.

.. rubric:: References:

.. [#f1] https://cyberstoph.org/posts/2022/03/detecting-shadow-credentials/
.. [#f2] https://www.splunk.com/en_us/blog/security/you-bet-your-lsass-hunting-lsass-access.html
.. [#f3] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931
.. [#f4] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78
