.. _Library API:

--------------------
Level 4: Library API
--------------------

**Description**: Functions provided by libraries from an external source, such as the runtime environment.

While developing this guidance, the team knew there was a level between tooling and API. However, this was difficult to define clearly. Using SpecterOps’s 
example, we understood they defined a level within their capability abstraction diagrams called Managed API. This level included different language libraries, 
“which is an abstraction itself that allows programmers to focus on functionality without worrying about complex programming topics.” [#f1]_ 
In their example, they include the .NET class ``KerberosRequestorSecurityToken`` which enables the use of a Windows API function. However, Microsoft defines managed code 
as, “Code whose execution is managed by a runtime.” [#f2]_ This doesn’t encompass items that don’t 
hit the disk or unmanaged code, in which “the programmer is in charge of pretty much everything." [#f3]_ 
The Library API level attempts to combine the two and define various functions provided by libraries from an external source. This includes frameworks, DLLs, and 
COM methods.

**Why is the Library API level placed here?**

The Library API encompasses classes, packages, and methods which could potentially be shared by tools and implementations. It is the level that defines an 
observable which could house API calls used by multiple tools. This could allow a user to monitor certain DLL packages being loaded into their environment 
or interprocess communication that might look suspicious. Since these packages and tools can be so broad and include a lot of functions, we separated API 
functions from the library, and they are being tracked in the next level.

**Examples**: .NET framework, DLLs, COM Methods

Observables
^^^^^^^^^^^
+-------------------------------+-----------------------------------+------------------------------+
| Category                      | Observable Fields                 |   Observable Values          |
+===============================+===================================+==============================+
| Frameworks                    |  |                                | | .NET                       |
+-------------------------------+-----------------------------------+------------------------------+
| DLL Libraries                 |  |                                |                              |
+-------------------------------+-----------------------------------+------------------------------+

.. rubric:: References

.. [#f1] https://posts.specterops.io/capability-abstraction-fbeaeeb26384
.. [#f2] https://learn.microsoft.com/en-us/dotnet/standard/managed-code 
.. [#f3] https://learn.microsoft.com/en-us/dotnet/standard/managed-code 