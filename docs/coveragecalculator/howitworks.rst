How It Works
==============

Implementation Catalog
-------------------------



Sensor Mappings
----------------
This project produced a structured dataset of Windows Event Log reference fields indexed by Windows Event ID. The purpose of the dataset was to create a consistent set of XML fields found within common and advanced Windows Security auditing events, and to provide a foundation for later analytic work.

The work was limited to documenting the published XML structure and normalizing to appropriate fields. The derived data set does not directly interpret the meaning of individual fields or create specific detection mappings. 

The example below demonstrates how a Windows Event Log entry is mapped.

*Example Usage:*
::
   <System>
      <Provider Name="Microsoft-Windows-Security-Auditing"/>
      <EventID>4624</EventID>
      <Version>2</Version>
      ...
   </System>

   <EventData>
      <Data Name="SubjectUserSid"/>
      <Data Name="SubjectUserName"/>
      <Data Name="SubjectDomainName"/>
      <Data Name="TargetUserSid"/>
      <Data Name="TargetUserName"/>
      <Data Name="TargetDomainName"/>
      <Data Name="LogonType"/>
      <Data Name="IpAddress"/>
      <Data Name="IpPort"/>
   </EventData>

*System Fields*

=========================  ==========================================
XML field                  Reference field
=========================  ==========================================
Provider.Name              System.Provider.Name
EventID                    System.EventID
Version                    System.Version
TimeCreated.SystemTime     System.TimeCreated.SystemTime
Computer                   System.Computer
=========================  ==========================================

*Event Data Fields*

=========================  ==========================================
XML field                  Reference field
=========================  ==========================================
SubjectUserSid             EventData.SubjectUserSid
SubjectUserName            EventData.SubjectUserName
SubjectDomainName          EventData.SubjectDomainName
TargetUserSid              EventData.TargetUserSid
TargetUserName             EventData.TargetUserName
TargetDomainName           EventData.TargetDomainName
LogonType                  EventData.LogonType
IpAddress                  EventData.IpAddress
IpPort                     EventData.IpPort
=========================  ==========================================
+—————––+–––––––––––––+


Analytic Ingestion
---------------------



Scoring Dictionary
--------------------
