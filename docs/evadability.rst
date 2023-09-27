.. _Robustness and Boolean Logic:

Combining Observables
=====================

Real-world analytics often incorporate multiple observables, so we now turn our
attention to scoring groups of observables, in particular the evaluation of boolean
expressions in analytics.

Robustness as a Metric
----------------------

Robustness is a metric that we have devised to give a relative score for the difficulty
an attacker would have in evading a candidate analytic when executing a given technique.
Robustness is determined by the lowest level that an analytic contains (according to our
levels of robustness) that could be evaded by an adversary and lead to a successful
attack. Thus, the highest robustness level (7) requires the adversary to make a costly
change to their TTPs, whereas the lowest level (1) requires only quick and inexpensive
changes to.

Evaluating Robustness
---------------------

Let **R(X)** be the Robustness Level for a given analytic.

  - If the analytic contains a single observable O, then the following rule applies:
      - **R(X) → R(O)**. That is, the robustness of the analytic evaluates to the
        robustness of the observable.
  - If the analytic contains multiple observables, then the following boolean logic applies:
      - **R(A AND B) → MIN(R(A), R(B))** - With the boolean operator "AND", the
        adversary only needs to evade either A or B, which makes the robustness equal to
        the lesser of the two observables.
      - **R((A AND B) | A) → R(B)** - The robustness level of A and B predicated on
        observing A is equivalent to the robustness level of B, since observing A is a
        given in this context.
      - **R(A OR B) → MAX(R(A), R(B))** - With the boolean operator "OR", the adversary
        needs to evade both A and B, which makes the robustness equal to the greater of
        the two observables. Note a special case where two observables at level 4 happen
        to cover all possible implementations, then that would raise the boolean OR
        expression to level 5.
      - **R(NOT A) → R(A)** - The robustness level of NOT A would be equivalent to the
        robustness level of the observable A itself, since the detection focus is still
        at A’s level of robustness.

Precision and Recall
--------------------

Although precision and recall are outside the scope of this project, we briefly touch on
how these metrics are affected by boolean expressions:

    - OR and IN operators expand the search aperture, which increases recall (but might
      tradeoff some precision)
    - AND operators shrink the aperture, which decreases recall (but might improve
      precision)

We do not try to claim that maximizing recall or maximizing precision makes for the best
analytic, as it is highly dependent on what the objective of the analytic is and the
environment it is being used in.
