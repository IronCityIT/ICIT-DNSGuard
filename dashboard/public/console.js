/*
 * Iron City DNS Guard — operator console.
 *
 * Three things this file takes seriously, because each of them is a way a
 * console like this normally fails:
 *
 * 1. It degrades. Every panel loads independently and renders its own loading,
 *    empty, error and degraded states. One dead endpoint costs you one card, not
 *    the page. Requests retry with backoff and jitter, but only GETs — retrying
 *    a POST could apply a change twice, and a duplicated policy publish is worse
 *    than an error message.
 *
 * 2. It never builds markup out of data. Every value that came from the API goes
 *    in through textContent. Domain names, feed publishers and finding titles are
 *    attacker-influenced — a scanned domain can be named whatever the person who
 *    registered it wanted — and the existing free-scan page interpolates exactly
 *    those into innerHTML today.
 *
 * 3. It tells the truth about approvals. A 202 is not an error; it means the
 *    change was refused pending sign-off, and the console shows the request id
 *    and routes you to the queue rather than reporting a failure.
 *
 * No inline handlers and no inline script, so this page can be served under a
 * Content-Security-Policy with no 'unsafe-inline' at all.
 */

"use strict";

(function () {
  // ── configuration ──────────────────────────────────────────────────

  var API_BASE = window.DNSGUARD_API_BASE || "";
  var TIMEOUT_MS = 8000;
  var RETRIES = 3;
  var BASE_DELAY_MS = 400;
  var MAX_DELAY_MS = 4000;
  var STORAGE_KEY = "dnsguard.console";

  var state = {
    tenant: "",
    token: "",
    connected: false,
    tab: "overview",
    catalog: null
  };

  // ── tiny DOM helpers ───────────────────────────────────────────────

  function $(id) { return document.getElementById(id); }

  function el(tag, opts, children) {
    var node = document.createElement(tag);
    opts = opts || {};
    if (opts.className) { node.className = opts.className; }
    if (opts.text !== undefined && opts.text !== null) { node.textContent = String(opts.text); }
    Object.keys(opts).forEach(function (key) {
      if (key === "className" || key === "text" || key === "on") { return; }
      if (key === "hidden") { node.hidden = !!opts[key]; return; }
      node.setAttribute(key, opts[key]);
    });
    if (opts.on) {
      Object.keys(opts.on).forEach(function (event) { node.addEventListener(event, opts.on[event]); });
    }
    (children || []).forEach(function (child) {
      if (child === null || child === undefined) { return; }
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    });
    return node;
  }

  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }

  function replace(node, children) {
    clear(node);
    (Array.isArray(children) ? children : [children]).forEach(function (child) {
      if (child) { node.appendChild(child); }
    });
  }

  function when(value) {
    if (!value) { return "—"; }
    var parsed = new Date(value);
    return isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
  }

  function relativeDays(value) {
    if (!value) { return null; }
    var parsed = new Date(value).getTime();
    if (isNaN(parsed)) { return null; }
    return Math.round((parsed - Date.now()) / 86400000);
  }

  // ── state cards ────────────────────────────────────────────────────

  function loading(what) {
    return el("div", { className: "state" }, [
      el("span", { className: "spinner" }), " loading " + what + "…"
    ]);
  }

  function empty(message) {
    return el("div", { className: "state", text: message });
  }

  function errorCard(message, detail, retry) {
    var children = [
      el("strong", { text: message }),
      el("div", { className: "detail", text: detail || "" })
    ];
    if (retry) {
      children.push(el("button", { className: "small", text: "Try again", on: { click: retry } }));
    }
    return el("div", { className: "state error" }, children);
  }

  function banner(kind, message) {
    return el("div", { className: "banner " + kind, text: message });
  }

  function sevPill(severity) {
    var value = String(severity || "info").toLowerCase();
    return el("span", { className: "sev " + value, text: value });
  }

  // ── the API client ─────────────────────────────────────────────────

  function backoff(attempt) {
    // Full jitter, matching the server-side policy: uniform over [0, cap].
    var cap = Math.min(MAX_DELAY_MS, BASE_DELAY_MS * Math.pow(2, attempt - 1));
    return Math.random() * cap;
  }

  function sleep(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  }

  function ApiError(message, status, body) {
    this.name = "ApiError";
    this.message = message;
    this.status = status;
    this.body = body || {};
  }
  ApiError.prototype = Object.create(Error.prototype);

  function once(path, options) {
    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, TIMEOUT_MS);
    var init = {
      method: options.method || "GET",
      signal: controller.signal,
      headers: {
        "X-Client-Id": state.tenant,
        "X-Actor": state.actor || state.tenant,
        "Accept": "application/json"
      }
    };
    if (state.token) { init.headers.Authorization = "Bearer " + state.token; }
    if (options.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.body);
    }

    return fetch(API_BASE + path, init).then(function (response) {
      clearTimeout(timer);
      return response.text().then(function (raw) {
        var body = {};
        if (raw) {
          try { body = JSON.parse(raw); } catch (err) { body = { detail: raw }; }
        }
        if (response.ok) { return body; }
        throw new ApiError(body.detail || response.statusText || "request failed", response.status, body);
      });
    }, function (err) {
      clearTimeout(timer);
      // An aborted request is a timeout from the user's point of view; saying
      // "AbortError" to an operator explains nothing.
      throw new ApiError(
        err && err.name === "AbortError" ? "the request timed out after " + (TIMEOUT_MS / 1000) + "s"
                                         : "could not reach the control plane",
        0, {}
      );
    });
  }

  function api(path, options) {
    options = options || {};
    var method = options.method || "GET";
    // Only idempotent requests are retried. Re-sending a POST could publish a
    // policy or grant an exception twice.
    var attempts = method === "GET" ? RETRIES : 1;

    function attempt(n) {
      return once(path, options).catch(function (err) {
        var transient = err.status === 0 || err.status >= 500;
        if (n < attempts && transient) {
          return sleep(backoff(n)).then(function () { return attempt(n + 1); });
        }
        throw err;
      });
    }
    return attempt(1);
  }

  /* Load one panel section, handling every outcome the same way so no panel
     can forget one. `render` returns nodes; anything it throws becomes an error
     card with a working retry. */
  function load(target, what, fetcher, render) {
    replace(target, loading(what));
    return fetcher().then(function (data) {
      replace(target, render(data));
    }, function (err) {
      if (err.status === 401 || err.status === 403) {
        setConnection(false, err.status === 401 ? "not authorised" : "no access to this client");
      }
      replace(target, errorCard(
        "Could not load " + what,
        err.message,
        function () { load(target, what, fetcher, render); }
      ));
    });
  }

  // ── connection ─────────────────────────────────────────────────────

  function setConnection(ok, label) {
    state.connected = ok;
    var pill = $("conn");
    pill.className = "pill " + (ok ? "ok" : "bad");
    pill.textContent = label;
  }

  function saveSession() {
    // Convenience only, and per-browser. Wrapped because a browser configured to
    // block site data throws on access rather than returning null.
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ tenant: state.tenant }));
    } catch (err) { /* nothing to do; the console still works without it */ }
  }

  function restoreSession() {
    var params = new URLSearchParams(window.location.search);
    var tenant = params.get("client") || "";
    if (!tenant) {
      try {
        var saved = JSON.parse(window.localStorage.getItem(STORAGE_KEY) || "{}");
        tenant = saved.tenant || "";
      } catch (err) { tenant = ""; }
    }
    $("tenant").value = tenant;
  }

  function connect() {
    state.tenant = $("tenant").value.trim();
    state.token = $("token").value;
    if (!state.tenant) {
      showGlobal("warn", "Enter the client id this console should act on.");
      return;
    }
    saveSession();
    setConnection(false, "connecting…");

    api("/readyz").then(function (health) {
      var degraded = health.status !== "ready";
      setConnection(true, degraded ? "degraded" : "connected");
      $("conn").className = "pill " + (degraded ? "warn" : "ok");
      if (degraded) {
        showGlobal("warn", "The control plane is degraded: " +
          (health.open_circuits.length ? "shedding calls to " + health.open_circuits.join(", ")
                                       : "a dependency is not answering") + ".");
      } else {
        hideGlobal();
      }
      renderTab(state.tab);
      refreshApprovalCount();
    }, function (err) {
      setConnection(false, "unavailable");
      showGlobal("bad", "Cannot reach the control plane: " + err.message);
    });
  }

  function showGlobal(kind, message) {
    var node = $("global-banner");
    node.hidden = false;
    replace(node, banner(kind, message));
  }

  function hideGlobal() { $("global-banner").hidden = true; }

  // ── approvals: the shared 202 path ─────────────────────────────────

  /* Every disruptive call funnels through here so the "refused pending
     approval" outcome is presented identically wherever it happens. */
  function gated(path, options, describe, after) {
    return api(path, options).then(function (result) {
      showGlobal("ok", describe + " — applied.");
      if (after) { after(result); }
      return result;
    }, function (err) {
      if (err.status === 202 && err.body.approval_request_id) {
        showGlobal("warn",
          describe + " needs approval before it takes effect. Request " +
          err.body.approval_request_id + " is now in the approvals queue for someone else to review.");
        refreshApprovalCount();
        return null;
      }
      showGlobal("bad", describe + " failed: " + err.message);
      throw err;
    });
  }

  function refreshApprovalCount() {
    if (!state.connected) { return; }
    api("/api/v1/tenants/" + encodeURIComponent(state.tenant) + "/approvals").then(function (data) {
      var badge = $("approval-count");
      var count = (data.approvals || []).length;
      badge.hidden = count === 0;
      badge.textContent = String(count);
    }, function () { /* the badge is decoration; its failure is not worth a banner */ });
  }

  function tenantPath(suffix) {
    return "/api/v1/tenants/" + encodeURIComponent(state.tenant) + suffix;
  }

  // ── panels ─────────────────────────────────────────────────────────

  function renderOverview(target) {
    load(target, "the overview", function () {
      // Each part is fetched independently and a failure in one is rendered as
      // a degraded card rather than failing the whole view.
      return Promise.all([
        api(tenantPath("/sites")).catch(function (e) { return { error: e }; }),
        api(tenantPath("/feeds")).catch(function (e) { return { error: e }; }),
        api(tenantPath("/approvals")).catch(function (e) { return { error: e }; }),
        api(tenantPath("/alerts?state=open")).catch(function (e) { return { error: e }; }),
        api(tenantPath("/compliance")).catch(function (e) { return { error: e }; })
      ]);
    }, function (parts) {
      var sites = parts[0], feeds = parts[1], approvals = parts[2];
      var alerts = parts[3], compliance = parts[4];
      var cards = [];

      cards.push(statCard("Sites", sites, function (d) {
        var all = d.sites || [];
        var enforcing = all.filter(function (s) { return s.enforcing; }).length;
        return {
          value: enforcing + " / " + all.length,
          label: "enforcing",
          note: all.length && enforcing < all.length
            ? (all.length - enforcing) + " site(s) in monitor mode — decisions are recorded, not applied"
            : ""
        };
      }));

      cards.push(statCard("Threat feeds", feeds, function (d) {
        var all = d.feeds || [];
        var stale = all.filter(function (f) { return f.stale; }).length;
        return {
          value: (all.length - stale) + " / " + all.length,
          label: "fresh",
          note: d.degraded ? "feed health unavailable: " + d.reason
              : stale ? stale + " feed(s) stale — their entries cannot justify new blocks" : ""
        };
      }));

      cards.push(statCard("Awaiting approval", approvals, function (d) {
        var all = d.approvals || [];
        return {
          value: String(all.length),
          label: "change(s) pending",
          note: all.length ? "Protection changes are not applied until reviewed." : ""
        };
      }));

      cards.push(statCard("Open alerts", alerts, function (d) {
        var all = d.alerts || [];
        var worst = all.filter(function (a) { return a.severity === "critical" || a.severity === "high"; });
        return { value: String(all.length), label: "open", note: worst.length ? worst.length + " at high severity or above" : "" };
      }));

      cards.push(complianceCard(compliance));
      return el("div", { className: "grid" }, cards);
    });
  }

  function statCard(title, data, project) {
    if (data.error) {
      return el("div", { className: "card" }, [
        el("h3", { text: title }),
        el("div", { className: "state error" }, [
          el("strong", { text: "Unavailable" }),
          el("div", { className: "detail", text: data.error.message })
        ])
      ]);
    }
    var view = project(data);
    var children = [
      el("h3", { text: title }),
      el("div", { className: "metric", text: view.value }),
      el("div", { className: "metric-label", text: view.label })
    ];
    if (view.note) { children.push(el("p", { className: "small muted", text: view.note })); }
    return el("div", { className: "card" }, children);
  }

  function complianceCard(data) {
    if (data.error) {
      return statCard("Compliance", data, function () { return {}; });
    }
    var totals = (data.coverage && data.coverage.totals) || {};
    var assessed = (totals.satisfied || 0) + (totals.deficient || 0);
    var rate = assessed ? Math.round((totals.satisfied || 0) / assessed * 100) : 0;
    var chainOk = data.audit_chain && data.audit_chain.valid;

    return el("div", { className: "card" }, [
      el("h3", { text: "Compliance" }),
      el("div", { className: "metric", text: rate + "%" }),
      el("div", { className: "metric-label", text: "of assessed controls satisfied" }),
      el("div", { className: "bar-track" }, [
        el("div", { className: "bar-fill" + (rate >= 80 ? " ok" : rate < 50 ? " bad" : ""),
                    style: "width:" + rate + "%" })
      ]),
      el("p", { className: "small muted", text:
        (totals.deficient || 0) + " deficient, " + (totals.not_assessed || 0) +
        " not assessed (outside what a DNS product can see)." }),
      el("p", { className: "small" }, [
        el("span", { className: "tag " + (chainOk ? "live" : "stale"),
                     text: chainOk ? "audit chain verified" : "AUDIT CHAIN BROKEN" })
      ])
    ]);
  }

  function renderPolicy(target) {
    load(target, "policies", function () { return api(tenantPath("/policies")); }, function (data) {
      var policies = data.policies || [];
      if (!policies.length) {
        return empty("No policy has been drafted for this client yet.");
      }
      return el("div", { className: "stack" }, policies.map(function (policy) {
        var rows = (policy.history || []).slice().reverse().map(function (version) {
          return el("tr", {}, [
            el("td", {}, [el("span", { className: "mono", text: "v" + version.version })]),
            el("td", {}, [stateTag(version.state)]),
            el("td", { text: String(version.rules) }),
            el("td", { className: "mono small", text: (version.content_hash || "").slice(0, 12) }),
            el("td", { className: "small" }, [
              el("div", { text: version.published_by ? "published by " + version.published_by : "drafted by " + version.created_by }),
              el("div", { className: "muted", text: when(version.published_at || version.created_at) }),
              version.rollback_of ? el("div", { className: "muted", text: "rollback of v" + version.rollback_of }) : null
            ]),
            el("td", {}, versionActions(policy.policy_id, version))
          ]);
        });

        return el("div", { className: "card" }, [
          el("h3", { text: policy.policy_id }),
          el("div", { className: "table-wrap" }, [
            el("table", {}, [
              el("thead", {}, [el("tr", {}, [
                el("th", { text: "Version" }), el("th", { text: "State" }), el("th", { text: "Rules" }),
                el("th", { text: "Content hash" }), el("th", { text: "By" }), el("th", { text: "" })
              ])]),
              el("tbody", {}, rows)
            ])
          ])
        ]);
      }));
    });
  }

  function stateTag(value) {
    var live = value === "published";
    var pending = value === "in_review" || value === "draft";
    return el("span", {
      className: "tag" + (live ? " live" : pending ? " gated" : ""),
      text: String(value).replace(/_/g, " ")
    });
  }

  function versionActions(policyId, version) {
    var actions = [];
    var base = tenantPath("/policies/" + encodeURIComponent(policyId));

    if (version.state === "draft") {
      actions.push(el("button", { className: "small", text: "Submit for review", on: { click: function () {
        api(base + "/versions/" + version.version + "/submit", { method: "POST" })
          .then(function () { renderTab("policy"); },
                function (err) { showGlobal("bad", "Could not submit: " + err.message); });
      } } }));
    }
    if (version.state === "draft" || version.state === "in_review") {
      actions.push(el("button", { className: "small primary", text: "Publish", on: { click: function () {
        gated(base + "/versions/" + version.version + "/publish", { method: "POST" },
              "Publishing " + policyId + " v" + version.version,
              function () { renderTab("policy"); });
      } } }));
    }
    if (version.state === "superseded" || version.state === "rolled_back") {
      actions.push(el("button", { className: "small danger", text: "Roll back to this", on: { click: function () {
        gated(base + "/rollback/" + version.version, { method: "POST" },
              "Rolling " + policyId + " back to v" + version.version,
              function () { renderTab("policy"); });
      } } }));
    }
    return [el("div", { className: "row" }, actions)];
  }

  function renderApprovals(target) {
    load(target, "the approvals queue", function () {
      return api(tenantPath("/approvals?state=pending"));
    }, function (data) {
      var pending = data.approvals || [];
      if (!pending.length) {
        return empty("Nothing is waiting for approval.");
      }
      return el("div", { className: "table-wrap" }, [
        el("table", {}, [
          el("thead", {}, [el("tr", {}, [
            el("th", { text: "Change" }), el("th", { text: "Requested by" }),
            el("th", { text: "Requested" }), el("th", { text: "Expires" }), el("th", { text: "" })
          ])]),
          el("tbody", {}, pending.map(function (request) {
            return el("tr", {}, [
              el("td", {}, [
                el("div", { text: request.summary || request.action }),
                el("div", { className: "small muted mono", text: request.subject }),
                el("div", { className: "small muted mono", text: "payload " + (request.payload_hash || "").slice(0, 16) })
              ]),
              el("td", { text: request.requested_by }),
              el("td", { className: "small", text: when(request.requested_at) }),
              el("td", { className: "small", text: when(request.expires_at) }),
              el("td", {}, [el("div", { className: "row" }, [
                el("button", { className: "small primary", text: "Approve", on: { click: function () {
                  decide(request.id, true);
                } } }),
                el("button", { className: "small danger", text: "Reject", on: { click: function () {
                  decide(request.id, false);
                } } })
              ])])
            ]);
          }))
        ])
      ]);
    });
  }

  function decide(requestId, approve) {
    var reason = window.prompt(approve ? "Why are you approving this?" : "Why are you rejecting this?", "");
    if (reason === null) { return; }
    api(tenantPath("/approvals/" + encodeURIComponent(requestId) + "/decision"),
        { method: "POST", body: { approve: approve, reason: reason } })
      .then(function () {
        showGlobal("ok", "Decision recorded. The requester can now apply the change.");
        renderTab("approvals");
        refreshApprovalCount();
      }, function (err) {
        // The commonest rejection here is separation of duties, and the API
        // says so in plain words — pass it straight through.
        showGlobal("bad", "Could not record the decision: " + err.message);
      });
  }

  function renderSites(target) {
    load(target, "sites", function () { return api(tenantPath("/sites")); }, function (data) {
      var sites = data.sites || [];
      if (!sites.length) { return empty("No sites are defined for this client."); }

      return el("div", { className: "table-wrap" }, [
        el("table", {}, [
          el("thead", {}, [el("tr", {}, [
            el("th", { text: "Site" }), el("th", { text: "Kind" }), el("th", { text: "Policy" }),
            el("th", { text: "Mode" }), el("th", { text: "" })
          ])]),
          el("tbody", {}, sites.map(function (site) {
            return el("tr", {}, [
              el("td", {}, [
                el("div", { text: site.name }),
                el("div", { className: "small muted mono", text: site.id })
              ]),
              el("td", { text: site.kind }),
              el("td", { className: "small", text: site.policy_id || "inherits the client baseline" }),
              el("td", {}, [
                el("span", { className: "tag " + (site.enforcing ? "live" : "gated"),
                             text: site.enforcing ? "enforcing" : "monitor only" })
              ]),
              el("td", {}, [
                el("button", {
                  className: "small " + (site.enforcing ? "danger" : "primary"),
                  text: site.enforcing ? "Stop enforcing" : "Start enforcing",
                  on: { click: function () { toggleEnforcement(site); } }
                })
              ])
            ]);
          }))
        ])
      ]);
    });
  }

  function toggleEnforcement(site) {
    var turningOff = site.enforcing;
    var message = turningOff
      ? "Stop enforcing policy at " + site.name + "?\n\nProtection is removed. Blocked names will resolve again."
      : "Start enforcing policy at " + site.name + "?\n\nNames the policy blocks will stop resolving for users at this site.";
    if (!window.confirm(message)) { return; }

    gated(tenantPath("/sites/" + encodeURIComponent(site.id) + "/enforcement"),
          { method: "PUT", body: { enforcing: !site.enforcing } },
          (turningOff ? "Disabling" : "Enabling") + " enforcement at " + site.name,
          function () { renderTab("sites"); });
  }

  function renderFeeds(target) {
    load(target, "threat feeds", function () { return api(tenantPath("/feeds")); }, function (data) {
      var nodes = [];
      if (data.degraded) {
        nodes.push(banner("warn", "Feed health could not be read: " + data.reason +
                                  ". What is shown may be out of date."));
      }
      var feeds = data.feeds || [];
      if (!feeds.length) {
        nodes.push(empty("No threat feeds are registered for this client."));
        return nodes;
      }
      var stale = feeds.filter(function (f) { return f.stale; });
      if (stale.length) {
        nodes.push(banner("warn", stale.length + " feed(s) have gone stale. Their entries can still be " +
                                  "reported but will not be used to justify a new block."));
      }
      nodes.push(el("div", { className: "table-wrap" }, [
        el("table", {}, [
          el("thead", {}, [el("tr", {}, [
            el("th", { text: "Feed" }), el("th", { text: "Publisher" }), el("th", { text: "Category" }),
            el("th", { text: "Trust" }), el("th", { text: "Entries" }), el("th", { text: "Last refresh" }),
            el("th", { text: "Checksum" }), el("th", { text: "State" })
          ])]),
          el("tbody", {}, feeds.map(function (feed) {
            return el("tr", {}, [
              el("td", { text: feed.name }),
              el("td", { text: feed.publisher }),
              el("td", { text: feed.category }),
              el("td", { text: feed.trust_tier }),
              el("td", { text: String(feed.entry_count) }),
              el("td", { className: "small", text: when(feed.last_success) }),
              el("td", { className: "mono small", text: (feed.sha256 || "").slice(0, 12) || "—" }),
              el("td", {}, [
                el("span", { className: "tag " + (feed.stale ? "stale" : "live"),
                             text: feed.stale ? "stale" : "fresh" }),
                feed.enabled ? null : el("span", { className: "tag", text: "disabled" }),
                feed.failed_fetches ? el("span", { className: "tag stale",
                                                   text: feed.failed_fetches + " failed fetch(es)" }) : null
              ])
            ]);
          }))
        ])
      ]));
      return nodes;
    });
  }

  function renderAnalytics(target) {
    var input = el("textarea", {
      rows: "6", placeholder: '[{"timestamp":"2026-01-01T00:00:00Z","tenant_id":"…","site_id":"hq","name":"evil.example","action":"block"}]',
      style: "width:100%"
    });
    var output = el("div", {});

    function analyse() {
      var events;
      try {
        events = JSON.parse(input.value || "[]");
      } catch (err) {
        replace(output, errorCard("That is not valid JSON", err.message, null));
        return;
      }
      if (!Array.isArray(events)) {
        replace(output, errorCard("Expected a list of decision events", "The top level must be a JSON array.", null));
        return;
      }
      replace(output, loading("the analysis"));
      api(tenantPath("/analytics/summary"), { method: "POST", body: { events: events } })
        .then(function (data) { replace(output, analyticsView(data)); },
              function (err) { replace(output, errorCard("Could not analyse the stream", err.message, analyse)); });
    }

    replace(target, [
      el("div", { className: "card" }, [
        el("h3", { text: "Decision stream" }),
        el("p", { className: "small muted", text:
          "Decisions are supplied here rather than stored, so the control plane never becomes a query-log warehouse." }),
        input,
        el("div", { className: "row", style: "margin-top:10px" }, [
          el("button", { className: "primary", text: "Analyse", on: { click: analyse } })
        ])
      ]),
      output
    ]);
  }

  function analyticsView(data) {
    var summary = data.summary || {};
    var cards = [
      metricCard("Lookups", summary.total_queries, "decisions in the stream"),
      metricCard("Blocked", summary.blocked, Math.round((summary.block_rate || 0) * 1000) / 10 + "% of lookups"),
      metricCard("Suppressed", summary.would_block, "would have been blocked — monitor mode or a stale feed"),
      metricCard("Distinct names blocked", summary.unique_blocked_names, "unique domains")
    ];
    var lists = [
      rankCard("Most blocked names", summary.top_blocked_names),
      rankCard("By category", summary.top_categories),
      rankCard("By feed", summary.top_feeds),
      rankCard("By site", summary.blocked_by_site)
    ];
    return [
      el("div", { className: "grid" }, cards),
      el("div", { className: "grid", style: "margin-top:16px" }, lists)
    ];
  }

  function metricCard(title, value, note) {
    return el("div", { className: "card" }, [
      el("h3", { text: title }),
      el("div", { className: "metric", text: String(value === undefined ? 0 : value) }),
      el("div", { className: "metric-label", text: note })
    ]);
  }

  function rankCard(title, rows) {
    rows = rows || [];
    return el("div", { className: "card" }, [
      el("h3", { text: title }),
      rows.length ? el("table", {}, [el("tbody", {}, rows.map(function (row) {
        return el("tr", {}, [
          el("td", { className: "mono small", text: row.key || "—" }),
          el("td", { className: "right small", text: String(row.count) })
        ]);
      }))]) : el("p", { className: "small muted", text: "Nothing in this slice." })
    ]);
  }

  function renderAlerts(target) {
    load(target, "alerts", function () { return api(tenantPath("/alerts")); }, function (data) {
      var alerts = data.alerts || [];
      if (!alerts.length) { return empty("No alerts have been raised."); }
      return el("div", { className: "table-wrap" }, [
        el("table", {}, [
          el("thead", {}, [el("tr", {}, [
            el("th", { text: "Severity" }), el("th", { text: "Alert" }), el("th", { text: "Measured" }),
            el("th", { text: "Raised" }), el("th", { text: "State" }), el("th", { text: "" })
          ])]),
          el("tbody", {}, alerts.map(function (alert) {
            return el("tr", {}, [
              el("td", {}, [sevPill(alert.severity)]),
              el("td", {}, [
                el("div", { text: alert.rule_name }),
                el("div", { className: "small muted", text: alert.message })
              ]),
              el("td", { className: "small mono", text: alert.value + " vs " + alert.threshold }),
              el("td", { className: "small", text: when(alert.triggered_at) }),
              el("td", {}, [el("span", { className: "tag" + (alert.state === "resolved" ? " live" : ""),
                                         text: alert.state })]),
              el("td", {}, alert.state === "resolved" ? [] : [el("div", { className: "row" }, [
                alert.state === "open" ? el("button", { className: "small", text: "Acknowledge", on: { click: function () {
                  api(tenantPath("/alerts/" + encodeURIComponent(alert.id) + "/acknowledge"), { method: "POST" })
                    .then(function () { renderTab("alerts"); },
                          function (err) { showGlobal("bad", err.message); });
                } } }) : null,
                el("button", { className: "small primary", text: "Resolve", on: { click: function () {
                  var resolution = window.prompt("What was done about this?", "");
                  if (!resolution) { return; }
                  api(tenantPath("/alerts/" + encodeURIComponent(alert.id) + "/resolve"),
                      { method: "POST", body: { resolution: resolution } })
                    .then(function () { renderTab("alerts"); },
                          function (err) { showGlobal("bad", err.message); });
                } } })
              ])])
            ]);
          }))
        ])
      ]);
    });
  }

  function renderExceptions(target) {
    load(target, "exceptions", function () { return api(tenantPath("/exceptions")); }, function (data) {
      var records = data.exceptions || [];
      var nodes = [];
      var lapsing = records.filter(function (e) {
        var days = relativeDays(e.expires_at);
        return e.state === "active" && days !== null && days <= 30;
      });
      if (lapsing.length) {
        nodes.push(banner("warn", lapsing.length + " exception(s) lapse within 30 days. " +
                                  "When one lapses the name is blocked again."));
      }
      if (!records.length) {
        nodes.push(empty("No exceptions have been requested."));
        return nodes;
      }

      nodes.push(el("div", { className: "table-wrap" }, [
        el("table", {}, [
          el("thead", {}, [el("tr", {}, [
            el("th", { text: "Applies to" }), el("th", { text: "Scope" }), el("th", { text: "Reason" }),
            el("th", { text: "Requested by" }), el("th", { text: "Expires" }), el("th", { text: "State" }),
            el("th", { text: "" })
          ])]),
          el("tbody", {}, records.map(function (record) {
            var days = relativeDays(record.expires_at);
            return el("tr", {}, [
              el("td", { className: "mono", text: record.match_value }),
              el("td", { className: "small", text: record.scope }),
              el("td", { className: "small", text: record.reason }),
              el("td", { className: "small", text: record.requested_by }),
              el("td", { className: "small" }, [
                el("div", { text: when(record.expires_at) }),
                days !== null && record.state === "active"
                  ? el("div", { className: "muted", text: days >= 0 ? "in " + days + " day(s)" : "lapsed" })
                  : null
              ]),
              el("td", {}, [el("span", {
                className: "tag" + (record.state === "active" ? " live" : record.state === "pending" ? " gated" : ""),
                text: record.state
              })]),
              el("td", {}, exceptionActions(record))
            ]);
          }))
        ])
      ]));
      return nodes;
    });
  }

  function exceptionActions(record) {
    var path = tenantPath("/exceptions/" + encodeURIComponent(record.id));
    if (record.state === "pending") {
      return [el("button", { className: "small primary", text: "Grant", on: { click: function () {
        gated(path + "/grant", { method: "POST" },
              "Allowing " + record.match_value, function () { renderTab("exceptions"); });
      } } })];
    }
    if (record.state === "active") {
      return [el("button", { className: "small danger", text: "Revoke", on: { click: function () {
        if (!window.confirm("Revoke the exception allowing " + record.match_value +
                            "?\n\nThe name will be blocked again wherever policy says so.")) { return; }
        gated(path + "/revoke", { method: "POST" },
              "Revoking the exception for " + record.match_value, function () { renderTab("exceptions"); });
      } } })];
    }
    return [];
  }

  function renderEvidence(target) {
    load(target, "the audit log", function () { return api(tenantPath("/audit")); }, function (data) {
      var integrity = data.integrity || {};
      var nodes = [];

      nodes.push(banner(integrity.valid ? "ok" : "bad", integrity.valid
        ? "Audit chain verified: " + integrity.records + " record(s), unbroken."
        : "AUDIT CHAIN BROKEN at record " + integrity.broken_at + " — " + integrity.reason));

      nodes.push(el("div", { className: "card" }, [
        el("h3", { text: "Evidence pack" }),
        el("p", { className: "small muted", text:
          "Exports the audit chain, approvals, policy history, exceptions, feed snapshots and " +
          "compliance mapping as one hashed bundle that can be verified without this console." }),
        el("div", { className: "row", style: "margin-top:10px" }, [
          el("button", { className: "primary", text: "Export evidence pack", on: { click: exportEvidence } })
        ])
      ]));

      var records = (data.records || []).slice().reverse().slice(0, 200);
      nodes.push(el("div", { className: "table-wrap" }, [
        el("table", {}, [
          el("thead", {}, [el("tr", {}, [
            el("th", { text: "#" }), el("th", { text: "When" }), el("th", { text: "Who" }),
            el("th", { text: "Action" }), el("th", { text: "Subject" }), el("th", { text: "Outcome" }),
            el("th", { text: "Hash" })
          ])]),
          el("tbody", {}, records.map(function (row) {
            return el("tr", {}, [
              el("td", { className: "mono small", text: String(row.seq) }),
              el("td", { className: "small", text: when(row.timestamp) }),
              el("td", { className: "small", text: row.actor }),
              el("td", { className: "mono small", text: row.action }),
              el("td", { className: "mono small", text: row.subject }),
              el("td", {}, [el("span", {
                className: "tag" + (row.outcome === "executed" ? " live" : row.outcome === "denied" ? " stale" : " gated"),
                text: String(row.outcome).replace(/_/g, " ")
              })]),
              el("td", { className: "mono small", text: (row.hash || "").slice(0, 10) })
            ]);
          }))
        ])
      ]));
      return nodes;
    });
  }

  function exportEvidence() {
    showGlobal("warn", "Exporting…");
    api(tenantPath("/evidence"), { method: "POST" }).then(function (bundle) {
      showGlobal("ok", "Evidence pack exported. Manifest hash " + bundle.manifest_hash +
                       " covering " + Object.keys(bundle.manifest || {}).length + " section(s).");
      renderTab("evidence");
    }, function (err) {
      showGlobal("bad", "Could not export the evidence pack: " + err.message);
    });
  }

  function renderScan(target) {
    load(target, "the assessment catalogue", function () {
      if (state.catalog) { return Promise.resolve(state.catalog); }
      return api("/api/v1/catalog").then(function (data) { state.catalog = data; return data; });
    }, function (data) {
      var nodes = [];
      if (data.degraded) {
        nodes.push(banner("warn", "The assessment catalogue is unavailable: " + (data.reason || "unknown") +
                                  ". Policy and reporting are unaffected."));
      }
      var modules = data.modules || [];
      if (!modules.length) {
        nodes.push(empty("No assessment modules are available."));
        return nodes;
      }

      var target_input = el("input", { type: "text", placeholder: "domain, hostname, URL, IP or CIDR",
                                       style: "flex:1;min-width:240px" });
      var groupSelect = el("select", {}, (data.groups || []).map(function (group) {
        return el("option", { value: group, text: group });
      }));

      var checkboxes = modules.map(function (module) {
        var box = el("input", { type: "checkbox", value: module.name });
        box.dataset.groups = (module.groups || []).join(",");
        return el("label", { className: "check" }, [
          box,
          el("span", {}, [
            el("strong", { text: module.name }),
            el("span", { className: "desc", text: module.description }),
            el("span", { className: "desc", text: "accepts: " + (module.target_kinds || []).join(", ") })
          ])
        ]);
      });

      function applyGroup() {
        var chosen = groupSelect.value;
        checkboxes.forEach(function (label) {
          var box = label.querySelector("input");
          box.checked = (box.dataset.groups || "").split(",").indexOf(chosen) !== -1;
        });
        renderCommand();
      }

      var command = el("pre", { className: "mono small", style: "white-space:pre-wrap;word-break:break-all" });

      function renderCommand() {
        var selected = checkboxes
          .map(function (label) { return label.querySelector("input"); })
          .filter(function (box) { return box.checked; })
          .map(function (box) { return box.value; });
        var name = target_input.value.trim() || "<target>";
        // Rendered as text, never executed here. The console shows the exact
        // invocation so what the UI describes and what CI runs cannot drift.
        command.textContent = selected.length
          ? "python3 tools/scan.py --domain " + name + " --modules " + selected.join(",")
          : "python3 tools/scan.py --domain " + name + " --group " + groupSelect.value;
      }

      groupSelect.addEventListener("change", applyGroup);
      target_input.addEventListener("input", renderCommand);
      checkboxes.forEach(function (label) {
        label.querySelector("input").addEventListener("change", renderCommand);
      });

      nodes.push(el("div", { className: "card" }, [
        el("h3", { text: "What to assess" }),
        el("div", { className: "row" }, [
          target_input,
          el("label", { className: "small muted", for: "group" }, ["preset"]),
          groupSelect,
          el("button", { className: "small", text: "Apply preset", on: { click: applyGroup } })
        ]),
        el("fieldset", { style: "margin-top:14px" }, [
          el("legend", { text: "Checks" })
        ].concat(checkboxes)),
        el("h3", { style: "margin-top:16px", text: "Equivalent command" }),
        command
      ]));
      renderCommand();
      return nodes;
    });
  }

  // ── tabs ───────────────────────────────────────────────────────────

  var RENDERERS = {
    overview: renderOverview,
    policy: renderPolicy,
    approvals: renderApprovals,
    sites: renderSites,
    feeds: renderFeeds,
    analytics: renderAnalytics,
    alerts: renderAlerts,
    exceptions: renderExceptions,
    evidence: renderEvidence,
    scan: renderScan
  };

  function renderTab(name) {
    state.tab = name;
    Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (tab) {
      tab.setAttribute("aria-selected", String(tab.dataset.tab === name));
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-panel]"), function (panel) {
      panel.hidden = panel.dataset.panel !== name;
    });

    var body = $(name + "-body") || $("panel-" + name);
    if (!state.connected && name !== "scan") {
      replace(body, empty("Connect to a client to load this view."));
      return;
    }
    RENDERERS[name](body);
  }

  // ── wiring ─────────────────────────────────────────────────────────

  function init() {
    restoreSession();
    setConnection(false, "not connected");

    $("connect").addEventListener("click", connect);
    $("refresh").addEventListener("click", function () { renderTab(state.tab); refreshApprovalCount(); });
    $("token").addEventListener("keydown", function (event) {
      if (event.key === "Enter") { connect(); }
    });
    Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (tab) {
      tab.addEventListener("click", function () { renderTab(tab.dataset.tab); });
    });

    // A browser that has gone offline should say so rather than letting every
    // panel report a mysterious timeout.
    window.addEventListener("offline", function () {
      setConnection(false, "offline");
      showGlobal("bad", "This browser is offline. Nothing shown below is being refreshed.");
    });
    window.addEventListener("online", function () {
      hideGlobal();
      if (state.tenant) { connect(); }
    });

    renderTab("overview");
    if ($("tenant").value) { $("token").focus(); }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
