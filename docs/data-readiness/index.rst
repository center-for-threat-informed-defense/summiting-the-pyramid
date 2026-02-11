Telemetry Strategy & Readiness
================================

.. epigraph::

  Detection strength begins with the right telemetry. We prioritize high-value data collection, assess telemetry effectiveness, and ensure logging is configured to support robust behavioral inference.

------------------------

.. raw:: html

   <div class="container">
     <h2>Telemetry Strategy & Readiness Key Components</h2>
     <div class="btn-group-vertical btn-block">
         <button type="button" class="btn btn-primary btn-block" data-toggle="collapse" data-target="#one">Telemetry Capability Modeling</button>
         <div id="one" class="collapse">
       	   <br>Understanding what a telemetry source can and cannot support from a detection perspective<br>
           <ul>
              <li><a href="../data-readiness/min-telemetry-reqs">Minimum Telemetry Requirements</a></li>
           </ul>
         </div>
         <button type="button" class="btn btn-primary btn-block" data-toggle="collapse" data-target="#two">Data Collection Prioritization</button>
         <div id="two" class="collapse">
       	   <br>Choosing what telemetry to enable based on detection value<br>
           <ul>
              <li><a href="../data-readiness/telemetry-quality">Calculating Telemetry Quality (TQ) Score</a></li>
           </ul>
         </div>
         <button type="button" class="btn btn-primary btn-block" data-toggle="collapse" data-target="#three">Telemetry Effectiveness Assessment</button>
         <div id="three" class="collapse">
       	   <br>Evaluating how well a telemetry source supports robust detection<br>
           <ul>
              <li><a href="../analytic-design/detection-diagram">Detection Decomposition Diagram</a></li>
              <li><a href="../examples/usecases/index">Use Case Analysis</a></li>
           </ul>
         </div>
         <button type="button" class="btn btn-primary btn-block" data-toggle="collapse" data-target="#four">Logging Standards & Implementation</button>
         <div id="four" class="collapse">
       	   <br>Defining how telemetry must be configured to support analytics<br><br>
         </div>
         <button type="button" class="btn btn-primary btn-block" data-toggle="collapse" data-target="#five">Data Quality & Schema Engineering</button>
         <div id="five" class="collapse">
       	   <br>Ensuring data fields are reliable enough to build logic on<br><br>
         </div>
         <button type="button" class="btn btn-primary btn-block" data-toggle="collapse" data-target="#six">Entity & Context Modeling</button>
         <div id="six" class="collapse">
       	   <br>Creating consistent identity, host, and lineage models so analytics can infer intent<br><br>
         </div>
     </div>
   </div>

--------------------------------------------------




.. toctree::
    :maxdepth: 1
 
    min-telemetry-reqs
    telemetry-quality
