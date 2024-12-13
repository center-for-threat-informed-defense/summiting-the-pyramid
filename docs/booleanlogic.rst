.. _Robustness and Boolean Logic:

Combining Observables
=====================

Understanding Resistance to Adversary Change Over Time
------------------------------------------------------

The Summiting model provides a relative score for the difficulty an attacker would have in evading a candidate analytic when executing a given technique. This score is determined by the lowest level that an analytic contains that could be evaded by an adversary and lead to a successful attack. Thus, the highest level (5) requires the adversary to make a costly change to their TTPs, whereas the lowest level (1) requires only quick and inexpensive changes.

Evaluating Robustness
---------------------

Let **R(X)** be the Summiting Level for a given analytic.

  - If the analytic contains a single observable O, then the following rule applies:
      - **R(X) → R(O)** – That is, the robustness of the analytic evaluates to the
        robustness of the observable.
  - If the analytic contains multiple observables A & B, then the following Boolean logic applies:
      - **R(A AND B) → MIN(R(A), R(B))** – With the boolean operator "AND", the
        adversary only needs to evade either A or B, which makes the robustness equal to
        the lesser of the two observables.
      - **R((A AND B) | A) → R(B)** - The level of A and B predicated on
        observing A is equivalent to the level of B, since observing A is a
        given in this context.
      - **R(A OR B) → MAX(R(A), R(B))** - With the Boolean operator “OR”, the adversary needs to evade both A and B, which makes the score equal to the greater of the two observables. Note a special case where two observables at Level 4 happen to cover all possible implementations, then that would raise the Boolean OR expression to Level 5.
      - **R(NOT A) → R(A)** - The level of NOT A would be equivalent to the robustness level of the observable A itself, since the detection focus is still at A’s level.
  - However, if the analytic has a filter and Boolean logic, the following Boolean logic applies:
      - **R(A) and NOT(FILTER C AND FILTER D) → R(A) AND (NOT(FILTER C) OR NOT(FILTER D))** – The Boolean logic of the filter, more specifically the NOT clause, flips the operators within the filter itself. For this reason, a NOT AND would turn into an OR.

