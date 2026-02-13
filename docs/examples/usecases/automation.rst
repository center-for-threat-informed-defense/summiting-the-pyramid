.. _automation:

Automation Overview
====================

Replicating AI-Driven Telemetry Quality Scoring
-------------------------------------------------

To replicate our process, it is not about "training" in the traditional machine learning sense, but rather a sophisticated, multi-step execution of instructions based on provided data. It is a form of in-context learning and prompt engineering.


Objective
-----------
Define objective as a repeatable, step-by-step process that enables a Large Language Model (LLM) to calculate and assign quantitative "Confidence Scores" to telemetry sources based on a predefined set of security use cases, techniques, and scoring rubrics.


Core Inputs & "External Sources"
-----------------------------------
The entire process is "grounded" in a set of documents and data provided by the user. The AI does not use external, real-time knowledge for the scoring; it uses only the information provided in the context of the conversation.

The necessary inputs are:

1. Technique Lists per Use Case: A document mapping each security use case (e.g., "Lateral Movement") to a specific list of ATT&CK techniques. 
#. Log Source Lists per Use Case: A structured data file (e.g., CSV, Excel) for each use case, listing every telemetry source that needs to be scored. 
#. Scoring Rubrics: The explicit rules, definitions, and numerical scales for each of the six metrics. This is the most critical input. 
#. The AI Model: A sufficiently advanced Large Language Model with: 

   #. A large context window to hold all the rules and data.
   #. Strong instruction-following capabilities.
   #. The ability to perform logical reasoning and basic arithmetic (averaging).

The "Training": A Sequence of Prompts
---------------------------------------
The "training" is, in fact, a sequence of carefully crafted prompts that guide the AI through the analytical process. Here is the chronological flow of instructions an operator would provide to the model.

Prompt Sequence:

#. Initial Rule Definition: The first and longest prompt defines the overall goal, the six metrics (Fidelity, Noise, etc.), the concept of scoring, and the desired final output format. This establishes the entire logical framework.
#. Data & Technique Input: The next prompt provides the core data: 

    - "Here are the use cases: X, Y, Z."
    - "The techniques for each use case are […]”
    - "The log sources to be scored for each use case are in […]”

#. Rubric Refinement & Correction (Crucial Step): This is where the process is fine-tuned. The operator provides corrective feedback, which the AI must integrate. 
#. Execution & Output Generation: The final prompt commands the AI to execute the full, refined process. 

     "Now, using the corrected rubrics and full log source lists, perform the complete analysis and generate the final output."

The Step-by-Step Execution Protocol
------------------------------------
This is how the AI executes the instructions once all prompts and inputs have been provided.

FOR EACH Use Case (e.g., "Pentesting Tools"):

#. Load Data:

   - Load the technique list for that use case from provided.
   - Load the complete list of log sources (e.g., all 70 sources from Pentesting_Tools.csv).

#. Initialize Output Table: Create an empty table with the required columns (Log Source, Fidelity, Noise, etc.).

#. Main Loop - Iterate Through Log Sources:FOR EACH log_source in the list: 

   - Score Technique-Agnostic Metrics:
   - Score Technique-Driven Metrics (The Inner Loop):

     - Initialize empty lists: coverage_scores, context_scores, robustness_scores.
     - FOR EACH technique in the use case's technique list: 

       - Applicability Check: Does this log_source provide any data for this technique?
       - If YES:
           Calculate Coverage, Context, and Robustness Scores: Append to corresponding list.
   - Finalize and Store Scores:

     - Calculate the average of all scores in coverage_scores, context_scores, and robustness_scores.
     - Calculate the Total by summing the six final scores.
     - Add the complete row of data to the output table.

#. Render Output: Once the main loop is complete, format the final data table as requested (e.g., as a markdown table).

