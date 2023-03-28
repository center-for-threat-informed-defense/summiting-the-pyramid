Explaining the Levels
=====================

When developing the Summiting the Pyramid Project, we needed to determine how to group different observables, or parts of an analytic, and how to rank them. Currently, we have described these levels as the **Difficulty of Bypassing Analytic Observables**. There are seven levels which are grouped based on how difficult it is for an adversary to evade the analytic observable.

.. figure:: _static/levels_03232023.png
   :alt: Difficulty of Bypassing Analytic Observables
   :align: center

   Levels and Observables

We will describe and outline our research below on how we determined these different level.

Operational and Environmental Variables
---------------------------------------

**Description**: *Variables which are constantly changing due to running processes, applications, and users. These observables provide a snapshot in time.*

Operational and environmental variables capture the context of what is currently happening to a user, process, or system. This includes observables such as process IDs, hash values, domain names, file names, and others. While these observables provide context for an attack, they do little to outline the behaviors of both normal users and the adversary.

**Why are these observables the lowest level?**

These observables cannot be relied on to identify adversary behavior. These indicators take minimal effort for an adversary to change. A new hash value can be created if one bit is changed in a file. A file name can be obfuscated within an image. When building out analytics, these observables will mostly capture values which point to the context of a certain application, user, or process. While these observables can detect known malicious applications or processes, these will not detect anything new, or if the adversary decides to change an operational or environmental variable to evade detection. To ensure detection in-depth, these observables should be combined with other level observables.

Resources: http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html

Custom Software and Open-Source Applications
--------------------------------------------

**Description**: *These are tools that are custom-made by the adversary, which they control the code, functions, and binaries associated with them.*

Custom software and open-source applications provide users the flexibility to configure the tool to meet their specific needs. These include tools such as ADFind, Cobalt Strike, and others which the adversary can modify to accomplish their goal.

**Why are open-source applications placed here?**

Open-source tooling gives adversaries an additional outlet of configuration to evade certain detections. For example, if an analytic detection is identifying certain tool-specific configurations, an adversary can go into the open-source code, change it, and evade that detection. While this requires knowledge on the adversary to change the tool configuration without changing the tool capability, it gives an adversary flexibility to evade detection through the availability of application code itself.

Resources: https://posts.specterops.io/capability-abstraction-fbeaeeb26384

Native Tooling
--------------

**Description**: *Tools which are native to the OS. The adversary has minimal control in changing functions and protocols to make them specific for their attack.*

Native tooling represents tools that are native to the respective OS. For example, Windows has the Task Scheduler (schtasks.exe), ping (ping.exe) and WMI command line utility (wmic.exe). The observables that are offered in this level are similar to those offered in the open-source tooling level, such as signatures, tool-specific configurations, and command line arguments. The observable values for this level are dependent on the OS that is being defended.

**Why are native tools split from open-source tooling?**

Native tooling is less flexible than open-source applications, as an adversary has to behave and act with what is available to them through the tool. The configurations, command-line arguments, and other observables for this level will remain consistent with what is available for the tool.

Since the adversary cannot change the tool itself and it is managed by an organization, it is much more difficult to distinguish adversary behavior from benign behavior. This provides an opportunity for an adversary to blend into the computing environment, also known as a Living off the Land attack. It is likely that analytics utilizing native tool observables will need to be combined with other level’s observables, or require further research into low-variance behaviors of abusing these tools through MITRE ATT&CK techniques.

Resources: https://darktrace.com/blog/living-off-the-land-how-hackers-blend-into-your-environment, https://www.gdatasoftware.com/blog/2022/02/37248-living-off-the-land

Library API
-----------

**Description**: *Functions provided by libraries from an external source, such as the runtime environment.*

While developing this guidance, the team knew there was a level between tooling and API. However, this was difficult to define clearly. Using Specter Ops’s example, we understood they defined a level within their capability abstraction diagrams called Managed API. This level included different language libraries, “which is an abstraction itself that allows programmers to focus on functionality without worrying about complex programming topics (https://posts.specterops.io/capability-abstraction-fbeaeeb26384).” In their example, they include the .NET class KerberosRequestorSecurityToken which enables the use of a Windows API function. However, Microsoft defines managed code as, “Code whose execution is managed by a runtime (https://learn.microsoft.com/en-us/dotnet/standard/managed-code )” This doesn’t encompass items that don’t hit the disk or unmanaged code, in which “the programmer is in charge of pretty much everything” (https://learn.microsoft.com/en-us/dotnet/standard/managed-code ). The Library API level attempts to combine the two and define various functions provided by libraries from an external source. This includes frameworks, DLLs, and COM methods.

**Why is the Library API level placed here?**

The Library API encompasses classes, packages, and methods which could potentially be shared by tools and implementations. It is the level that defines an observable which could house API calls used by multiple tools. This could allow a user to monitor certain DLL packages being loaded into their environment or interprocess communication that might look suspicious. Since these packages and tools can be so broad and include a lot of functions, we separated API functions from the library, and they are being tracked in the next level.

Resources: https://learn.microsoft.com/en-us/dotnet/standard/managed-code , https://posts.specterops.io/capability-abstraction-fbeaeeb26384

OS (Subsystem) API
------------------

**Description**: *Defined by managed code and can be used individually to accomplish adversary objectives.*

API calls, as defined by Microsoft, can be used to, “perform tasks when it is difficult to write equivalent procedures of your own.” These functions are defined by the packages downloaded by the user or the system, such as DLLs and COM Methods, and can be managed or unmanaged. API calls allow the user to direct commands to the computer system, such as logging on a user (LogonUser), identifying errors on a thread (GetLastError), and others related to user interfaces, shell environment, and system services. It allows an adversary flexibility in utilizing different computer functions to manipulate computer systems towards their goals. However, it is limiting since these API calls are defined by the operating system. This level will be explicitly for the Windows OS, since other operating systems will interact directly with the kernel through system calls.

**Why should we track API calls?**

API calls allow a defender to focus on the certain capability of a tool compared to the tool itself. This potentially allows the creation of analytics that track similar behavior of API calls, called low-variance behaviors, across multiple different tools, rather than building an analytic per tool. Now, certain API calls might hook specific events. Johnny Johnson’s research focuses on attaching API calls to Windows Event IDs and Sysmon Event IDs that they may trigger. For example, LogonUserA will trigger the 4624-event code. However, this is not true for all events. Monitoring API calls can be extremely difficult. However, further static and dynamic research can uncover potential links to event-codes, or lower-level calls that can be tracked otherwise.

Resources: https://learn.microsoft.com/en-us/dotnet/visual-basic/programming-guide/com-interop/walkthrough-calling-windows-apis , https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list , https://docs.google.com/spreadsheets/d/1Y3MHsgDWj_xH4qrqIMs4kYJq1FSuqv4LqIrcX24L10A/edit#gid=0 

System Calls
------------

**Description**: *Transition from user mode to kernel mode.*

System calls are where user-mode applications executed in CPU Ring 3 pass control to the kernel-mode functions executed in CPU Ring 0 with privileged access. The user-mode application has little visibility and control to what happens at this level. This includes kernel-drivers and functions that call upon the kernel directly to complete tasks. These system calls are usually implemented by storing values in system registers to indicate which functionality is requested, followed by an interrupt signal in assembly. These low-level actions are usually performed by C wrapper functions. In Windows, these system call C wrapper functions usually start with Nt or Zw. In other operating systems, these C wrapper functions are usually included in libc. However, these wrapper function can be bypassed in user-mode by directly setting the appropriate register(s) and invoking the direct system call interrupt. System calls also include the actions resulting from routines, such as file manipulation or communication protection.

**Why is System Calls relevant for detections?**

System calls provide another level of abstraction for adversaries to utilize within their tools. If there are system calls that are available to use and do not trigger alerts or events within the operating system, it might be more appealing for an adversary to skip the previous levels and use system calls. Like the previous level, it might be more difficult for defenders to detect the use of system calls and true positives of malicious activity. The further up you go through this leveling, the more likely adversary behavior will be blended in with benign behavior. However, it does indicate that it is more difficult for an adversary to evade these system calls, as they will be directly interfacing with the operating system.

Resources: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-nt-and-zw-versions-of-the-native-system-services-routines , https://github.com/j00ru/windows-syscalls 

Kernel and Interface Observables
--------------------------------

As defined by Microsoft, the kernel, “implements the core functionality that everything else in the operating system depends upon.” This is the heart of the Operating System, as it provides the services for everything, including managing threads, conflicts and errors, and memory space. Some of the kernel library support routines available start with Ke within the Windows Operating System. Defenders can monitor kernel activity through observables including registry modification, some event IDs, and network protocols. 

**Why are kernel and interface detections at the top of detection observables?**

Kernel is the last level of the Operating System until you get to changing tactics to tampering with the hardware of the computer. If an adversary can access calls to these routines, they can bypass every other documented layer and blend in with the other kernel threads and routines occurring. However, the higher the adversaries climb up the levels, the harder they fall. Directly interfacing with the kernel has a greater possibility of breaking the operating system since everything is managed and run in a particular way. This is also the hardest level for a defender to detect. Context and monitoring abnormal processes can assist in identifying potential malicious activity. Overall, kernel behavior showcases the most robust fields to an analytic, since this will be the most difficult to evade.

Resources: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-kernel-library , https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/_kernel/#core-kernel-library-support-routines , https://www.techtarget.com/searchdatacenter/definition/kernel 
