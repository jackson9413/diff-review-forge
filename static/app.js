/* Diff Review Forge - front end. Vanilla JS, no build step, no dependencies. */
(function () {
  "use strict";

  var state = { result: null, samples: [], profiles: [] };

  function $(id) { return document.getElementById(id); }

  function esc(value) {
    if (value === null || value === undefined) { return ""; }
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function toast(message) {
    var el = document.createElement("div");
    el.className = "toast";
    el.textContent = message;
    document.body.appendChild(el);
    window.setTimeout(function () { el.remove(); }, 2600);
  }

  function verdictColor(score) {
    if (score >= 90) { return "#3fb950"; }
    if (score >= 75) { return "#7ee787"; }
    if (score >= 60) { return "#f5d442"; }
    if (score >= 40) { return "#ff9f43"; }
    return "#ff5c5c";
  }

  function fillColor(score) {
    if (score >= 75) { return "#3fb950"; }
    if (score >= 60) { return "#f5d442"; }
    if (score >= 40) { return "#ff9f43"; }
    return "#ff5c5c";
  }

  /* ---------------------------------------------------------------- boot */

  async function boot() {
    try {
      var health = await (await fetch("/api/health")).json();
      $("engine-badge").textContent =
        "engine " + health.version + " / " + health.rule_count + " rules / " + health.profiles.length + " profiles";
    } catch (err) {
      $("engine-badge").textContent = "engine unreachable";
    }
    try {
      var prof = await (await fetch("/api/profiles")).json();
      state.profiles = prof.profiles;
      var select = $("profile");
      prof.profiles.forEach(function (item) {
        var opt = document.createElement("option");
        opt.value = item.key;
        opt.textContent = item.label;
        select.appendChild(opt);
      });
      select.addEventListener("change", function () { updateBlurb(); });
      updateBlurb();
    } catch (err) { /* profiles are optional */ }
    try {
      var sam = await (await fetch("/api/samples")).json();
      state.samples = sam.samples;
      renderSamples();
    } catch (err) { /* samples are optional */ }
    loadRuns();

    $("review-btn").addEventListener("click", runReview);
    $("clear-btn").addEventListener("click", function () {
      $("diff-input").value = "";
      updateStats();
    });
    $("diff-input").addEventListener("input", updateStats);
    $("save-run").addEventListener("click", saveRun);
    Array.prototype.forEach.call(document.querySelectorAll("[data-export]"), function (btn) {
      btn.addEventListener("click", function () { exportReport(btn.getAttribute("data-export")); });
    });
    Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (tab) {
      tab.addEventListener("click", function () { selectTab(tab.getAttribute("data-tab")); });
    });
    updateStats();
  }

  function updateBlurb() {
    var key = $("profile").value;
    state.profiles.forEach(function (item) {
      if (item.key === key) { $("profile-blurb").textContent = item.blurb; }
    });
  }

  function updateStats() {
    var text = $("diff-input").value;
    var lines = text ? text.split("\n").length : 0;
    $("input-stats").textContent = lines ? lines + " lines pasted" : "";
  }

  function renderSamples() {
    var wrap = $("sample-list");
    wrap.innerHTML = "";
    state.samples.forEach(function (sample) {
      var btn = document.createElement("button");
      btn.className = "sample";
      btn.innerHTML = "<strong>" + esc(sample.title) + "</strong><span>" + esc(sample.blurb) + "</span>";
      btn.addEventListener("click", function () {
        if (sample.profile) { $("profile").value = sample.profile; updateBlurb(); }
        loadSampleDiff(sample.id);
      });
      wrap.appendChild(btn);
    });
  }

  async function loadSampleDiff(id) {
    var response = await fetch("/api/samples/" + encodeURIComponent(id));
    if (!response.ok) { toast("Could not load the sample"); return; }
    var payload = await response.json();
    $("diff-input").value = payload.diff;
    updateStats();
    runReview();
  }

  /* -------------------------------------------------------------- review */

  async function runReview() {
    var diff = $("diff-input").value;
    if (!diff.trim()) {
      showError("Paste a diff first.");
      return;
    }
    var btn = $("review-btn");
    btn.disabled = true;
    btn.textContent = "Reviewing...";
    try {
      var response = await fetch("/api/review", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ diff: diff, profile: $("profile").value })
      });
      var data = await response.json();
      if (!response.ok) {
        showError(data.error || "Review failed.");
        return;
      }
      state.result = data;
      render(data);
      $("empty-state").hidden = true;
      $("results").hidden = false;
    } catch (err) {
      showError("Could not reach the review engine: " + err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "Review this diff";
    }
  }

  function showError(message) {
    var existing = document.querySelector(".error-box");
    if (existing) { existing.remove(); }
    var box = document.createElement("div");
    box.className = "error-box";
    box.textContent = message;
    var panel = document.querySelector(".result-panel");
    panel.insertBefore(box, panel.firstChild);
    window.setTimeout(function () { box.remove(); }, 6000);
  }

  function render(result) {
    renderVerdict(result);
    $("summary-text").textContent = result.summary;
    renderAxes(result);
    renderFindings(result);
    renderFiles(result);
    renderPlan(result);
    renderCoverage(result);
  }

  function renderVerdict(result) {
    var score = result.score;
    var banner = $("verdict-banner");
    var color = verdictColor(score.overall);
    var counts = score.counts;
    banner.innerHTML =
      '<div class="score" style="color:' + color + '">' + score.overall + "</div>" +
      "<div>" +
      "<h3>" + esc(score.verdict_label) + "</h3>" +
      "<p>" + esc(score.verdict_note) + "</p>" +
      "</div>" +
      '<div class="meta">' +
      esc(result.meta.profile_label) + "<br>" +
      result.meta.files + " files &nbsp;+" + result.meta.additions + " &nbsp;-" + result.meta.deletions + "<br>" +
      counts.critical + " critical &nbsp;" + counts.high + " high &nbsp;" +
      counts.medium + " medium &nbsp;" + counts.low + " low" +
      "</div>";
    var existing = document.querySelector(".caps");
    if (existing) { existing.remove(); }
    if (score.caps && score.caps.length) {
      var caps = document.createElement("div");
      caps.className = "caps";
      var items = score.caps.map(function (c) {
        return "<li>" + esc(c.reason) + "</li>";
      }).join("");
      caps.innerHTML = "<h4>Structural caps applied</h4><ul>" + items + "</ul>";
      banner.parentNode.insertBefore(caps, banner.nextSibling);
    }
  }

  function renderAxes(result) {
    var wrap = $("axis-bars");
    wrap.innerHTML = "";
    result.score.axes.forEach(function (axis) {
      var row = document.createElement("div");
      row.className = "axis-row" + (axis.applicable ? "" : " off");
      var track = document.createElement("div");
      track.className = "track";
      var fill = document.createElement("div");
      fill.className = "fill";
      fill.style.width = Math.max(0, Math.min(100, axis.score)) + "%";
      fill.style.background = fillColor(axis.score);
      track.appendChild(fill);
      var label = axis.label + (axis.applicable ? "" : " (n/a)") +
        (axis.cap ? " - capped at " + axis.cap : "");
      row.innerHTML = '<div class="name">' + esc(label) + "</div>";
      row.appendChild(track);
      var val = document.createElement("div");
      val.className = "val";
      val.textContent = axis.score + " (" + axis.findings + ")";
      row.appendChild(val);
      wrap.appendChild(row);
    });
  }

  function renderFindings(result) {
    var wrap = $("tab-findings");
    wrap.innerHTML = "";
    if (!result.findings.length) {
      wrap.innerHTML = '<p class="muted">No findings. This diff looks clean.</p>';
      return;
    }
    result.findings.forEach(function (f) {
      var card = document.createElement("div");
      card.className = "finding " + f.severity;
      var location = f.path + (f.line ? ":" + f.line : "");
      card.innerHTML =
        '<div class="head"><span class="sev">' + esc(f.severity_label) + "</span>" +
        '<span class="title">' + esc(f.title) + "</span>" +
        '<span class="loc">' + esc(location) + "</span></div>" +
        '<div class="evidence">' + esc(f.evidence) + "</div>" +
        '<div class="why"><strong>Why it matters:</strong> ' + esc(f.why) + "</div>" +
        '<div class="fix"><strong>Fix:</strong> ' + esc(f.fix) + "</div>" +
        '<div class="actions"></div>';
      var actions = card.querySelector(".actions");
      if (f.comment) {
        var copy = document.createElement("button");
        copy.className = "ghost small";
        copy.textContent = "Copy review comment";
        copy.addEventListener("click", function () {
          var text = f.comment + " (" + location + ")";
          if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(function () { toast("Comment copied"); });
          } else {
            toast(text);
          }
        });
        actions.appendChild(copy);
      }
      var meta = document.createElement("span");
      meta.className = "muted";
      meta.textContent = f.axis_label + " - rule " + f.rule + " - " + f.id;
      actions.appendChild(meta);
      wrap.appendChild(card);
    });
  }

  function renderFiles(result) {
    var wrap = $("tab-files");
    wrap.innerHTML = "";
    if (!result.files.length) {
      wrap.innerHTML = '<p class="muted">No files in this diff.</p>';
      return;
    }
    var rows = result.files.map(function (row) {
      var reasons = row.risk_reasons.length ? row.risk_reasons.join(", ") : "-";
      return "<tr><td class='path'>" + esc(row.path) + "</td><td>" + esc(row.status) +
        "</td><td>" + esc(row.language) + "</td><td>+" + row.additions + " / -" + row.deletions +
        "</td><td>" + row.findings + "</td><td><span class='riskbar'><span style='width:" +
        Math.min(100, row.risk) + "%'></span></span> " + row.risk +
        "<div class='muted'>" + esc(reasons) + "</div></td></tr>";
    }).join("");
    var html = "<table><thead><tr><th>File</th><th>Status</th><th>Language</th>" +
      "<th>Lines</th><th>Findings</th><th>Risk</th></tr></thead><tbody>" + rows + "</tbody></table>";
    var hotspots = result.hotspots || [];
    if (hotspots.length) {
      html += "<h3 style='margin-top:18px;font-size:13px'>Review these first</h3><ul>";
      hotspots.forEach(function (hot) {
        html += "<li><strong>" + esc(hot.path) + "</strong> - risk " + hot.risk + ", " +
          hot.findings + " finding(s)" +
          (hot.risk_reasons.length ? " (" + esc(hot.risk_reasons.join(", ")) + ")" : "") + "</li>";
      });
      html += "</ul>";
    }
    wrap.innerHTML = html;
  }

  function renderPlan(result) {
    var wrap = $("tab-plan");
    wrap.innerHTML = "";
    if (!result.plan.length) {
      wrap.innerHTML = '<p class="muted">Nothing to fix - the plan is empty.</p>';
      return;
    }
    result.plan.forEach(function (step) {
      var row = document.createElement("div");
      row.className = "plan-step";
      row.innerHTML =
        '<div class="n">' + step.step + "</div>" +
        '<div class="body"><div><strong>' + esc(step.title) + "</strong> " +
        '<span class="muted">- ' + esc(step.axis_label) + ", " + step.count + " finding(s)</span></div>" +
        '<div class="action">' + esc(step.action) + "</div>" +
        '<div class="action">Score after this fix: ' + step.score_after +
        " (files: " + esc(step.paths.join(", ")) + ")</div></div>" +
        '<div class="gain">' + (step.gain > 0 ? "+" + step.gain : step.gain) + "</div>";
      wrap.appendChild(row);
    });
  }

  function renderCoverage(result) {
    var wrap = $("tab-coverage");
    var cov = result.coverage;
    var breaking = result.breaking_changes || [];
    var html = "<dl class='kv'>" +
      "<dt>Source files changed</dt><dd>" + cov.source_files + "</dd>" +
      "<dt>Test files changed</dt><dd>" + cov.test_files + "</dd>" +
      "<dt>Note</dt><dd>" + esc(cov.note) + "</dd>" +
      "<dt>Languages</dt><dd>" + esc(result.meta.languages.join(", ") || "none") + "</dd>" +
      "<dt>Reviewed at</dt><dd>" + esc(result.meta.reviewed_at) + "</dd>" +
      "</dl>";
    if (breaking.length) {
      html += "<h3 style='margin-top:18px;font-size:13px'>Breaking changes</h3><ul>";
      breaking.forEach(function (bc) {
        html += "<li><strong>" + esc(bc.title) + "</strong> (" + esc(bc.path) + ") - " + esc(bc.detail) + "</li>";
      });
      html += "</ul>";
    }
    wrap.innerHTML = html;
  }

  function selectTab(name) {
    Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (tab) {
      tab.classList.toggle("active", tab.getAttribute("data-tab") === name);
    });
    Array.prototype.forEach.call(document.querySelectorAll(".tab-panel"), function (panel) {
      panel.classList.toggle("active", panel.id === "tab-" + name);
    });
    if (name === "runs") { loadRuns(); }
  }

  /* ------------------------------------------------------------- exports */

  async function exportReport(format) {
    if (!state.result) { toast("Run a review first"); return; }
    var response = await fetch("/api/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ diff: $("diff-input").value, profile: $("profile").value, format: format })
    });
    if (!response.ok) {
      var err = await response.json();
      toast(err.error || "Export failed");
      return;
    }
    var blob = await response.blob();
    var names = { md: "code-review.md", json: "code-review.json", csv: "code-review-findings.csv" };
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.href = url;
    link.download = names[format];
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    toast("Exported " + names[format]);
  }

  async function saveRun() {
    var diff = $("diff-input").value;
    if (!diff.trim()) { toast("Nothing to save"); return; }
    var title = $("run-title").value.trim();
    var rating = $("run-rating").value;
    var response = await fetch("/api/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        diff: diff,
        profile: $("profile").value,
        title: title,
        rating: rating ? parseInt(rating, 10) : null
      })
    });
    if (!response.ok) {
      var err = await response.json();
      toast(err.error || "Could not save the run");
      return;
    }
    toast("Run saved");
    loadRuns();
    selectTab("runs");
  }

  async function loadRuns() {
    try {
      var response = await fetch("/api/runs");
      var data = await response.json();
      var wrap = $("tab-runs");
      if (!data.runs.length) {
        wrap.innerHTML = '<p class="muted">No saved reviews yet.</p>';
        return;
      }
      var rows = data.runs.map(function (run) {
        return "<tr><td class='path'>" + esc(run.title) + "</td><td>" + esc(run.profile) +
          "</td><td>" + esc(run.verdict) + "</td><td>" + run.score +
          "</td><td>" + run.files + " files</td><td>" + (run.rating ? run.rating + " star(s)" : "-") +
          "</td><td>" + esc(run.created_at) + "</td></tr>";
      }).join("");
      wrap.innerHTML = "<table><thead><tr><th>Title</th><th>Profile</th><th>Verdict</th><th>Score</th>" +
        "<th>Diff</th><th>Rating</th><th>When</th></tr></thead><tbody>" + rows + "</tbody></table>";
    } catch (err) { /* the run log is optional */ }
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
