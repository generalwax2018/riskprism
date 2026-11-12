/* Small progressive enhancements. The app works without them; nothing here builds HTML from data. */
(function () {
  "use strict";
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  // Portfolio: filter chips + search over server-rendered rows.
  var rows = $("#vendor-rows");
  if (rows) {
    var state = { f: "all", q: "" };
    var tests = {
      all: function () { return true; },
      t1: function (r) { return r.dataset.res === "T1"; },
      ai: function (r) { return r.dataset.ai === "1"; },
      human: function (r) { return r.dataset.human === "1"; },
      auto: function (r) { return r.dataset.human === "0"; }
    };
    var apply = function () {
      var shown = 0;
      $all(".prow", rows).forEach(function (r) {
        var ok = tests[state.f](r) && (!state.q || (r.dataset.name || "").indexOf(state.q) !== -1);
        r.hidden = !ok;
        if (ok) shown++;
      });
      var none = $("#no-match");
      if (none) none.hidden = shown !== 0;
    };
    $all("[data-filter]").forEach(function (b) {
      b.addEventListener("click", function () {
        state.f = b.dataset.filter;
        $all("[data-filter]").forEach(function (o) { o.classList.toggle("on", o === b); o.setAttribute("aria-pressed", o === b ? "true" : "false"); });
        apply();
      });
    });
    var search = $("#vendor-search");
    if (search) search.addEventListener("input", function () { state.q = search.value.trim().toLowerCase(); apply(); });
  }

  // Alerts: severity filter.
  var flagBox = $("#flag-rows");
  if (flagBox) {
    $all("[data-sev-filter]").forEach(function (b) {
      b.addEventListener("click", function () {
        var want = b.dataset.sevFilter;
        $all("[data-sev-filter]").forEach(function (o) { o.classList.toggle("on", o === b); });
        $all(".frow", flagBox).forEach(function (r) { r.hidden = want !== "all" && r.dataset.sev !== want; });
      });
    });
  }

  // Vendor record tabs.
  var tabs = $all("[data-tab]");
  if (tabs.length) {
    tabs.forEach(function (t) {
      t.addEventListener("click", function () {
        tabs.forEach(function (o) {
          var on = o === t;
          o.classList.toggle("on", on);
          o.setAttribute("aria-selected", on ? "true" : "false");
        });
        $all("[data-panel]").forEach(function (p) { p.hidden = p.dataset.panel !== t.dataset.tab; });
      });
    });
    // Jumping to the risk acceptance form from the banner needs the overview tab.
    var ra = $('a[href="#risk-acceptance"]');
    if (ra) ra.addEventListener("click", function () { var o = $('[data-tab="overview"]'); if (o) o.click(); });
    // Links like /vendor/<slug>#threat or #integrations open that tab.
    var want = location.hash.slice(1);
    tabs.forEach(function (t) { if (want && t.dataset.tab === want) t.click(); });
  }

  // Risk acceptance: suggested expiry chips fill the date field; the signer can still type any date.
  var acceptForm = $(".accept-form");
  if (acceptForm) {
    var until = $('input[name="until"]', acceptForm);
    var tierSel = $('select[name="risk_tier"]', acceptForm);
    var opts = $all(".expiry-opt", acceptForm);
    var mark = function () {
      opts.forEach(function (o) { o.classList.toggle("picked", !!until && o.dataset.date === until.value); });
    };
    opts.forEach(function (o) {
      o.addEventListener("click", function () { if (until) { until.value = o.dataset.date; mark(); } });
    });
    if (until) until.addEventListener("input", mark);
    if (tierSel) tierSel.addEventListener("change", function () {
      opts.forEach(function (o) { o.classList.toggle("suggested", !!o.dataset.tier && o.dataset.tier === tierSel.value); });
    });
    mark();
  }

  // AI questionnaire: reload while a draft is being researched.
  if ($("[data-ai-running]")) setTimeout(function () { window.location.reload(); }, 6000);

  // Copy buttons.
  $all("[data-copy]").forEach(function (b) {
    b.addEventListener("click", function () {
      var src = $(b.dataset.copy);
      if (!src) return;
      var text = src.textContent;
      var done = function () { var old = b.textContent; b.textContent = "Copied"; setTimeout(function () { b.textContent = old; }, 1500); };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, function () {});
      else { var r = document.createRange(); r.selectNode(src); var s = window.getSelection(); s.removeAllRanges(); s.addRange(r); }
    });
  });

  // Vendor questionnaire: progress.
  var form = $("#portal-form");
  if (form) {
    var groups = $all(".q", form);
    var fill = $("#progress-fill"), count = $("#progress-count"), total = $("#progress-total");
    var answered = function (g) {
      var radios = $all('input[type="radio"]', g);
      if (radios.length && radios.some(function (r) { return r.checked; })) return true;
      if ($all('input[type="file"]', g).some(function (f) { return f.files && f.files.length; })) return true;
      if ($all('input[type="checkbox"]', g).some(function (c) { return c.checked; })) return true;
      return $all('textarea, input.text', g).some(function (i) { return i.value.trim() !== ""; });
    };
    var update = function () {
      var n = groups.filter(answered).length;
      if (total) total.textContent = String(groups.length);
      if (count) count.textContent = String(n);
      if (fill) fill.style.width = (groups.length ? Math.round(100 * n / groups.length) : 0) + "%";
    };
    form.addEventListener("input", update);
    form.addEventListener("change", update);
    update();
  }
})();
