(function() {
  try {
    var params = new URLSearchParams(location.search);
    var encoded = params.get("trace") || "";
    if (!encoded) throw new Error("No trace data in URL.");
    var json = decodeURIComponent(escape(atob(encoded)));
    var trace = JSON.parse(json);
    if (!trace.v) throw new Error("Invalid trace format.");
    var desc = document.getElementById("desc");
    desc.textContent = "Tab " + (trace.tabId || "?") + " — " + (trace.startedAt ? new Date(trace.startedAt).toLocaleString() : "unknown date");
    var stats = document.getElementById("stats");
    stats.innerHTML =
      '<span class="stat"><strong>' + trace.summary.eventCount + '</strong> events</span>' +
      '<span class="stat"><strong>' + trace.summary.findingCount + '</strong> findings</span>' +
      '<span class="stat"><strong>' + trace.summary.problemCount + '</strong> problems</span>' +
      '<span class="stat"><strong>' + trace.summary.warningCount + '</strong> warnings</span>';
    var err = document.getElementById("error");
    if (trace.findings && trace.findings.length > 0) {
      err.style.display = "block";
      err.innerHTML = "<strong>Findings (" + trace.findings.length + "):</strong><br>" +
        trace.findings.map(function(f) {
          return (f.severity === "error" ? "[PROBLEM] " : f.severity === "warning" ? "[WARNING] " : "[INFO] ") +
            f.title + " (" + f.ruleId + ")";
        }).join("<br>");
    }
    var tr = document.getElementById("trace");
    tr.style.display = "block";
    tr.textContent = JSON.stringify(trace, null, 2);
  } catch (e) {
    document.getElementById("desc").textContent = "Failed to load trace.";
    var errEl = document.getElementById("error");
    errEl.style.display = "block";
    errEl.textContent = e.toString();
  }
})();
