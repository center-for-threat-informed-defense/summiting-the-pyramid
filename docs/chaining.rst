.. _Chaining Analytics:

Chaining Analytics
=====================

**Understand the Differences Between “Loose” and “Direct” Correlation**

There are two ways we can define the relationship between analytics we would
like to chain together. If we have CTI reporting of a specific adversary or
campaign that uses a specific set of activities, then a direct correlation is
appropriate. If we are looking at a trend from multiple adversaries or campaigns
with some common activities seen, then that is a loose correlation. 

  
Direct Correlation 
---------------------
Direct correlation is used when there is a clear focus on a specific campaign,
adversary, or tool. The most effective direct correlation analytics involve
actions that are dependent on one another. For example, an adversary performs an
initial action, and a subsequent action relies on the success of the first.
These dependent actions may originate from different data sources or occur in
different parts of the network, but their interdependence is key to establishing
a direct correlation. This method is straightforward, as the analytics are
chained together in a sequence where all actions must occur for the correlation
to be valid.

**Example:**

Let's assume we have reporting that an adversary uses three commands together to
accomplish a singular task, and the use of those commands individually would not
achieve the same goal. This is a case of a direct correlation and we want all
conditions to be met before triggering an alert. 


 Analytic1 AND Analytic2 AND Analytic3

All three analytics need to be triggered for this to create a alert. 

  
Loose Correlation 
---------------------
Loose correlation is applied when there is only a general idea of the
adversary's behavior, rather than precise knowledge of the specific actions they
will take. A good example of this is discovery activity, which occurs frequently
on networks and can be difficult to distinguish as either normal behavior or
adversary activity. For instance, system information discovery may be observed
across multiple systems, while remote file share discovery may occur on a
different set of systems. Individually, these actions may appear benign, but
when multiple techniques converge on a single system or user, they begin to form
a pattern that suggests adversary activity.

**Example:**

Now let's assume we see several commands that are used to achieve an action by
the adversary, but that action can be achieved with a few different options. We
consider that a loose correlation. Our detection analytic will include all of
the known combinations, but we set a threshold where we need to see *n*
conditions met for an alert to trigger. This threshold reduces false positives
while still capturing the activity.  

 Analytic1 OR Analytic2 OR Analytic3 

 Distinct_Count (Analytic_ID) by Host 

 Where Distinct_count >=2 

We are looking at three activities and counting the number of alerts that go
off. Importantly this is a distinct count meaning that even if Analytic1 goes
off 10 times it is only counted once. Then we set a threshold where if 2 or more
go off, an alert is triggered.

Importantly, loose correlation does not account for the order in which actions
occur, making it less complex to implement compared to methods that rely on
strict sequencing.

While some implementations attempt to enforce strict sequencing, we have found
that this approach can be challenging to implement effectively. The complexity
and cost of such implementations often outweigh the benefits, and adoption of
these types of analytics have been limited in practice. Loose correlation, by
contrast, offers a more practical and scalable solution, allowing organizations
to adapt thresholds and analytics to their specific environments while
maintaining a balance between detection accuracy and operational feasibility.
