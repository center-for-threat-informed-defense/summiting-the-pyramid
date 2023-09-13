.. _Robustness and Boolean Logic:

Combining Observables
=====================

Real-world analytics often incorporate multiple observables, so we now turn our
attention to scoring groups of observables, in particular the evaluation of boolean
expressions in analytics.

Robustness as a Metric
----------------------

Robustness is a metric that we have devised to give a relative score for the difficulty
an attacker would have in evading a candidate analytic when executing a given Technique.
We are proposing that robustness value be determined by the lowest level that an
analytic contains (according to our levels of robustness) that could be evaded by an
adversary and lead to a successful attack.  Thus, a high robustness level, such as 7,
would mean that the adversary would have to evade detection by changing their approach
via interactions with the kernel or interfaces, whereas a low robustness level, such as
1, would mean that an adversary could evade detection through use of different
operational or environmental variables.

Robustness has a fairly strong correlation with robustness but is independent from how
robustness itself is scored.  Key differences include that robustness is focused on the
ability of an analytic to hold against a given attack, whereas robustness is focused on
the amount of effort it would take for an attacker to successfully evade a given
analytic - to simplify it a little more, robustness is centered on the attack, while
robustness is centered on the defense.

Evaluating Robustness
---------------------

Let **R(X)** be the Robustness Level for a given analytic.

  - If the analytic contains a single observable O, then the following rule applies:
      - **R(X) → R(O)**. That is, the robustness of the analytic evaluates to the
        robustness of the observable.
  - If the analytic contains multiple observables, then the following boolean logic applies:
      - **R(A AND B) → MIN(R(A), R(B)) [when A ∩ B ≠ ∅]** - The robustness level of A
        and B is equal to the lowest level value of the two observables, as long as
        there exists some overlap between the data that can be detected by each
        observable; if this were not true, the analytic would never return any results.
      - **R(A OR B) → MAX(R(A), R(B))** - The robustness level of A OR B is equal to the
        highest level value of the two observables; if A and B combined cover all
        possible implementations, then R(A OR B)=L5, even though R(A)=L4 and R(B)=L4
      - **R(NOT A) → R(A)** - The robustness level of NOT A would be equivalent to the
        robustness level of the observable A itself, since the detection focus is still
        at A’s level of robustness.
      - **R((A AND B) | A) → R(B)** - The robustness level of A and B predicated on
        observing A is equivalent to the robustness level of B, since observing A is a
        given in this context.

Precision and Recall
--------------------

Although precision and recall are outside the scope of this project, we briefly touch on
how these metrics are affected by boolean expressions:

    - OR and IN operators expand the search aperture, which increases recall (but might tradeoff some precision)
    - AND and NOT functions shrink the aperture, which decreases recall (but might improve precision)

We do not try to claim that maximizing recall or maximizing precision makes for the best
analytic, as it is highly dependent on what the objective of the analytic is and the
environment it is being used in.
