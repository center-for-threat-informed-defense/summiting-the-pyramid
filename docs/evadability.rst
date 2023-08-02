.. _Robustness and Boolean Logic:

Robustness & Boolean Logic
===========================

Now that the Summiting Team has developed the Levels of Robustness framework for categorizing individual observables used in analytics according to their difficulty to evade across 2 dimensions, we can open the aperture a bit more to explore how we can discover and categorize combinations of those observables in various analytics.  Oftentimes in real-world applications, an analytic consists of several observables chained together using some form of Boolean logic, and just as with the individual observables, it is extremely useful to have some objective indication of the robustness and strength of a composite analytic.  

.. figure:: _static/scheduled_task_capability_abstraction.png
   :alt: T1053 - Scheduled Task Capability Abstraction
   :align: center

   Example of Capability Abstraction for ATT&CK Technique T1053: Scheduled Task [#f1]_ [#f2]_

Basic Guidelines
----------------

In order to devise an objective method of categorizing complex analytics, we began by examining common Boolean logic operations and how they factor into important analytic metrics, including recall and precision, before concluding on our metric of robustness.

+-------------------------------------------------+-------------------------------------------------+
| Operations Increasing Recall/Limiting Precision | Operations Increasing Precision/Limiting Recall |
+=================================================+=================================================+
| OR                                              | AND                                             |
+-------------------------------------------------+-------------------------------------------------+
| IN                                              | NOT                                             |
+-------------------------------------------------+-------------------------------------------------+

Here we have determined a general set of guidelines for what effects the employment of Boolean logic has on an overall analytic:

    - OR and IN operations help to expand the aperture, most likely increasing recall but sacrificing some precision

    - AND and NOT functions constrain the aperture, most likely increasing precision but sacrificing some recall

We do not try to claim that maximizing recall or maximizing precision makes for the best analytic, as it is highly dependent on what the objective of the analytic is and the environment it is being used in.  We can, however, speak objectively on what effect various combinations of observables have on an analytic’s difficulty to evade, which brings us to our new metric, robustness.

Robustness as a Metric
----------------------

*Definition and Relationship to Robustness*

Robustness is a metric that we have devised to give a relative score for the difficulty an attacker would have in evading a candidate analytic when executing a given Technique.  We are proposing that robustness value be determined by the lowest level that an analytic contains (according to our levels of robustness) that could be evaded by an adversary and lead to a successful attack.  Thus, a high robustness level, such as 7, would mean that the adversary would have to evade detection by changing their approach via interactions with the kernel or interfaces, whereas a low robustness level, such as 1, would mean that an adversary could evade detection through use of different operational or environmental variables.

Robustness has a fairly strong correlation with robustness but is independent from how robustness itself is scored.  Key differences include that robustness is focused on the ability of an analytic to hold against a given attack, whereas robustness is focused on the amount of effort it would take for an attacker to successfully evade a given analytic - to simplify it a little more, robustness is centered on the attack, while robustness is centered on the defense.

Determining Robustness Level
----------------------------

Let *R(X)* be the Robustness Level for a given observable or analytic component X:

  - For an observable A, **R(A) = Level of Robustness of A**


In determining the Robustness Level *R(X)* for a more complex analytic, we can apply a set of Boolean logic rules to find the resulting value.  The set of rules below are for use in combining two analytic components at levels A and B:

  - **R(A AND B) → MIN(R(A), R(B)) [when A ∩ B ≠ ∅]** - The robustness level of A and B is equal to the lowest level value of the two observables, as long as there exists some overlap between the data that can be detected by each observable; if this were not true, the analytic would never return any results.
  
  - **R(A OR B) → MAX(R(A), R(B))** - The robustness level of A OR B is equal to the highest level value of the two observables; if A and B combined cover all possible implementations, then R(A OR B)=L5, even though R(A)=L4 and R(B)=L4
  
  - **R(NOT A) → R(A)** - The robustness level of NOT A would be equivalent to the robustness level of the observable A itself, since the detection focus is still at A’s level of robustness.
  
  - **R((A AND B) | A) → R(B)** - The robustness level of A and B predicated on observing A is equivalent to the robustness level of B, since observing A is a given in this context.

.. rubric:: References

.. [#f1] https://posts.specterops.io/abstracting-scheduled-tasks-3b6451f6a1c5
.. [#f2] https://mitre-engenuity.org/cybersecurity/mad/