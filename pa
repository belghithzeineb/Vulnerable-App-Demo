import React, { useCallback, useEffect, useMemo, useState } from "react";
const CLASSES = ["IDOR", "Numerical", "AuthBypass", "Logic"];

const DEFAULT_TRUTH = [
  { file: "routes/userProfile.ts", class: "IDOR" },
  { file: "routes/order.ts", class: "Numerical" },
  { file: "routes/basket.ts", class: "IDOR" },
  { file: "routes/feedback.ts", class: "Logic" },
  { file: "routes/logfileServer.ts", class: "IDOR" },
  { file: "routes/fileServer.ts", class: "IDOR" },
  { file: "routes/dataExport.ts", class: "IDOR" },
  { file: "routes/orderHistory.ts", class: "IDOR" },
  { file: "routes/updateProductReviews.ts", class: "IDOR" },
  { file: "routes/videoHandler.ts", class: "IDOR" },
];

function normFile(p) {
  const s = String(p || "").replace(/\\/g, "/");
  const i = s.lastIndexOf("routes/");
  return i >= 0 ? s.slice(i) : s.split("/").pop();
}

function classify(f) {
  const t = ["rule", "message", "vulnerability"]
    .map((k) => String((f && f[k]) || ""))
    .join(" ")
    .toLowerCase();

  if (/(sql|inject|xss|traversal|ssrf|command injection)/.test(t)) {
    return "Technical";
  }

  if (
    /(idor|ownership|owner|object-level|bola|authorization|access control|belongs to)/.test(
      t
    )
  ) {
    return "IDOR";
  }

  if (
    /(price|quantity|quantit|negative|refund|discount|coupon|total|balance|numerical|invariant)/.test(
      t
    )
  ) {
    return "Numerical";
  }

  if (/(role|admin|privilege|isadmin|escalat|client-controlled flag)/.test(t)) {
    return "AuthBypass";
  }

  if (
    /(workflow|state|transition|feedback|review|manipulat|business rule|logic)/.test(
      t
    )
  ) {
    return "Logic";
  }

  return "Other";
}

function perClass(truth, findings) {
  const byClass = {};

  CLASSES.forEach((c) => {
    byClass[c] = [];
  });

  (truth || []).forEach((g) => {
    byClass[g.class] = byClass[g.class] || [];
    byClass[g.class].push(normFile(g.file));
  });

  const rows = {};
  let gtp = 0;
  let gfp = 0;
  let gfn = 0;
  let tech = 0;
  let other = 0;

  CLASSES.forEach((c) => {
    const rem = [...(byClass[c] || [])];
    let tp = 0;
    let fp = 0;

    (findings || []).forEach((f) => {
      if (classify(f) !== c) {
        return;
      }

      const nf = normFile(f.file);
      const i = rem.indexOf(nf);

      if (i >= 0) {
        rem.splice(i, 1);
        tp += 1;
      } else {
        fp += 1;
      }
    });

    rows[c] = {
      gt: (byClass[c] || []).length,
      tp,
      fp,
      fn: rem.length,
    };

    gtp += tp;
    gfp += fp;
    gfn += rem.length;
  });

  (findings || []).forEach((f) => {
    const k = classify(f);

    if (k === "Technical") {
      tech += 1;
    } else if (k === "Other") {
      other += 1;
    }
  });

  return {
    rows,
    gtp,
    gfp: gfp + tech + other,
    tech,
    other,
    gfn,
    gtTotal: (truth || []).length,
  };
}

function pct(a, b) {
  return b ? ((a / b) * 100).toFixed(1) : "0.0";
}

function readJson(e, set) {
  const f = e.target.files && e.target.files[0];

  if (!f) {
    return;
  }

  const r = new FileReader();

  r.onload = () => {
    try {
      let d = JSON.parse(r.result);

      if (Array.isArray(d)) {
        d = { items: d };
      }

      set(d);
    } catch {
      alert("Invalid JSON file.");
    }
  };

  r.readAsText(f);
}

function asFindings(d) {
  if (!d) {
    return null;
  }

  if (Array.isArray(d)) {
    return d;
  }

  return d.findings || d.vulnerabilities || d.items || [];
}

function asTruth(d) {
  if (!d) {
    return DEFAULT_TRUTH;
  }

  if (Array.isArray(d)) {
    return d;
  }

  return d.truth || d.ground_truth || d.items || DEFAULT_TRUTH;
}

function FileInput({ label, onPick }) {
  return (
    <label className="lh-file-in">
      <span>{label}</span>
      <input type="file" accept="application/json,.json" onChange={onPick} />
    </label>
  );
}

function ClassTable({ pc }) {
  return (
    <table className="lh-eval-table">
      <thead>
        <tr>
          <th>Class</th>
          <th>GT</th>
          <th>TP</th>
          <th>FP</th>
          <th>FN</th>
          <th>Precision</th>
          <th>Recall</th>
        </tr>
      </thead>

      <tbody>
        {CLASSES.map((c) => {
          const r = pc.rows[c];

          return (
            <tr key={c}>
              <td>
                <b>{c}</b>
              </td>
              <td>{r.gt}</td>
              <td>{r.tp}</td>
              <td>{r.fp}</td>
              <td>{r.fn}</td>
              <td>{pct(r.tp, r.tp + r.fp)}%</td>
              <td>{pct(r.tp, r.tp + r.fn)}%</td>
            </tr>
          );
        })}

        <tr className="lh-eval-global">
          <td>
            <b>GLOBAL</b>
          </td>
          <td>{pc.gtTotal}</td>
          <td>{pc.gtp}</td>
          <td>{pc.gfp}</td>
          <td>{pc.gfn}</td>
          <td>{pct(pc.gtp, pc.gtp + pc.gfp)}%</td>
          <td>{pct(pc.gtp, pc.gtp + pc.gfn)}%</td>
        </tr>
      </tbody>
    </table>
  );
}

// ===================== SETTINGS =====================

export function Settings({ apiUrl }) {
  const [url, setUrl] = useState(
    localStorage.getItem("logichound_api_url") || apiUrl || ""
  );
  const [ping, setPing] = useState(null);

  const [systemStatus, setSystemStatus] = useState(null);
  const [systemLoading, setSystemLoading] = useState(false);
  const [systemError, setSystemError] = useState("");

  const loadSystemStatus = useCallback(async () => {
    setSystemLoading(true);
    setSystemError("");

    try {
      const response = await fetch(
        `${apiUrl.replace(/\/+$/, "")}/api/system/status`
      );

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();
      setSystemStatus(data);
    } catch (error) {
      setSystemError(error.message || "System status unavailable");
      setSystemStatus(null);
    } finally {
      setSystemLoading(false);
    }
  }, [apiUrl]);

  useEffect(() => {
    loadSystemStatus();
  }, [loadSystemStatus]);

  const test = async () => {
    setPing("…");

    try {
      const response = await fetch(url.replace(/\/+$/, "") + "/health", {
        method: "GET",
      });

      setPing(response.ok ? `OK (${response.status})` : `HTTP ${response.status}`);
    } catch (error) {
      setPing("UNREACHABLE — " + (error.message || error));
    }
  };

  const save = () => {
    localStorage.setItem("logichound_api_url", url.trim());
    window.location.reload();
  };

  const reset = () => {
    localStorage.removeItem("logichound_api_url");
    window.location.reload();
  };

  const statusClass = (status) => {
    const value = String(status || "").toLowerCase();

    if (value === "ok" || value === "healthy") {
      return "pass";
    }

    if (value === "down" || value === "error" || value === "unavailable") {
      return "fail";
    }

    return "warn";
  };

  const StatusCard = ({ title, status, detail, error }) => (
    <div className={`lh-system-card ${statusClass(status)}`}>
      <div className="lh-system-card-top">
        <strong>{title}</strong>
        <span className={`lh-score-pill ${statusClass(status)}`}>
          {status || "unknown"}
        </span>
      </div>

      {detail && <p>{detail}</p>}
      {error && <small>{error}</small>}
    </div>
  );

  return (
    <section className="lh-panel lh-settings">
      <div className="lh-panel-head">
        <h3>Settings</h3>
        <span className="lh-panel-sub">client-side configuration and system health</span>
      </div>

      <div className="lh-set-row">
        <label>Backend API URL</label>

        <div className="lh-set-ctl">
          <input
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="http://127.0.0.1:8001"
          />

          <button className="lh-btn-ghost" onClick={test}>
            Test connection
          </button>

          <button className="btn-primary lh-btn-sm" onClick={save}>
            Save &amp; reload
          </button>

          <button className="lh-btn-ghost" onClick={reset}>
            Reset
          </button>
        </div>

        <small>
          Effective URL: <code>{apiUrl}</code> · ping:{" "}
          <b>{ping === null ? "not tested" : ping}</b>
        </small>
      </div>

      <div className="lh-set-row">
        <div className="lh-panel-head" style={{ marginBottom: 10 }}>
          <h3>System status</h3>
          <button className="lh-btn-ghost lh-btn-sm" onClick={loadSystemStatus}>
            {systemLoading ? "Checking..." : "Refresh"}
          </button>
        </div>

        {systemError && (
          <p className="lh-recent-empty">
            Could not load system status: {systemError}
          </p>
        )}

        {!systemError && !systemStatus && (
          <p className="lh-recent-empty">
            {systemLoading ? "Loading system status..." : "No system data loaded."}
          </p>
        )}

        {systemStatus && (
          <div className="lh-system-grid">
            <StatusCard
              title="API Gateway"
              status={systemStatus.api?.status}
              detail={systemStatus.api?.service}
            />

            <StatusCard
              title="Redis Broker"
              status={systemStatus.redis?.status}
              detail="Celery broker/result backend"
              error={systemStatus.redis?.error}
            />

            <StatusCard
              title="Celery Workers"
              status={systemStatus.celery?.status}
              detail={`${systemStatus.celery?.workers ?? 0} worker(s) detected`}
              error={systemStatus.celery?.error}
            />

            <StatusCard
              title="Scan History DB"
              status={systemStatus.history_db?.status}
              detail={`${systemStatus.history_db?.scan_count ?? 0} stored scan(s)`}
              error={systemStatus.history_db?.error}
            />

            <StatusCard
              title="Gate Threshold"
              status="ok"
              detail={`${systemStatus.gate?.threshold ?? "30"} / 100`}
            />

            <StatusCard
              title="Risk Signing Secret"
              status={
                systemStatus.risk_acceptance?.signing_secret_configured
                  ? "ok"
                  : "down"
              }
              detail={
                systemStatus.risk_acceptance?.signing_secret_configured
                  ? "Configured"
                  : "Missing LOGICHOUND_TOKEN_SIGNING_SECRET"
              }
            />
          </div>
        )}
      </div>

      <div className="lh-set-row">
        <label>Severity model</label>

        <div className="lh-set-ctl">
          <code>critical · warning · low</code>
        </div>

        <small>
          Engine values such as <code>high</code> or <code>medium</code> are
          normalized into <code>warning</code>.
        </small>
      </div>
    </section>
  );
}

// ===================== HELP / DOCS =====================

export function HelpDocs() {
  const pages = [
    [
      "Dashboard",
      "Priority findings, production backlog with real fixed/net-new from history, and per-repo trends.",
    ],
    [
      "Projects",
      "One card per scanned repository, aggregated from scan history.",
    ],
    ["Findings", "Searchable, filterable finding list with a details inspector."],
    ["Reports", "Immutable audit log of every scan, with gate outcome."],
    [
      "LLM Evaluation",
      "Recorded AI baseline + per-class precision/recall from a loaded report.",
    ],
    [
      "AI Discovery",
      "Specialist-agent v2 status per vulnerability class.",
    ],
    [
      "Risk Acceptance",
      "Generate and document signed .logichound.sig risk-acceptance tokens.",
    ],
    ["Pull Requests", "How the GitHub merge gate is enforced."],
  ];

  return (
    <section className="lh-panel lh-help">
      <div className="lh-panel-head">
        <h3>Help &amp; documentation</h3>
      </div>

      <div className="lh-help-grid">
        <div className="lh-help-card">
          <h4>What LogicHound does</h4>
          <p>
            Audits a GitHub repository with Semgrep + SonarQube for technical
            flaws and a Llama-based engine for business-logic flaws such as
            IDOR, numerical manipulation, authorization bypass, and workflow
            abuse.
          </p>
        </div>

        <div className="lh-help-card">
          <h4>Severity model</h4>
          <p>
            <b className="c">Critical</b> ·{" "}
            <b className="w">Warning</b> ·{" "}
            <b className="l">Low</b>. LogicHound AI intentionally uses a compact
            three-level severity model to keep the merge gate and developer
            workflow simple.
          </p>
        </div>

        <div className="lh-help-card">
          <h4>The merge gate</h4>
          <p>
            Score ≥ 30 → pass. Score &lt; 30 → block, unless a valid signed{" "}
            <code>.logichound.sig</code> exists, in which case the merge is
            allowed in non-blocking risk-accepted mode. The scan always runs;
            the token never hides findings.
          </p>
        </div>

        <div className="lh-help-card">
          <h4>Scan history</h4>
          <p>
            Every audit is stored. The backlog&apos;s <i>fixed</i> and{" "}
            <i>net new</i> are fingerprint diffs vs the previous scan of the
            same repo; <i>ignored</i> is unavailable until triage exists.
          </p>
        </div>
      </div>

      <h4 style={{ marginTop: 18 }}>Sidebar pages</h4>

      <ul className="lh-help-pages">
        {pages.map(([n, d]) => (
          <li key={n}>
            <b>{n}</b>
            <span>{d}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

// ===================== LLM EVALUATION =====================

export function LlmEval() {
  const [fData, setFData] = useState(null);
  const [tData, setTData] = useState(null);

  const findings = asFindings(fData);
  const truth = asTruth(tData);

  const pc = useMemo(
    () => (findings ? perClass(truth, findings) : null),
    [findings, truth]
  );

  const gtCounts = useMemo(() => {
    const c = {
      IDOR: 0,
      Numerical: 0,
      AuthBypass: 0,
      Logic: 0,
    };

    truth.forEach((g) => {
      if (c[g.class] != null) {
        c[g.class] += 1;
      }
    });

    return c;
  }, [truth]);

  return (
    <section className="lh-panel lh-eval">
      <div className="lh-panel-head">
        <h3>LLM evaluation</h3>
        <span className="lh-panel-sub">business-logic detection quality</span>
      </div>

      <p className="lh-audit-note">
        Recorded general-prompt baseline on local OWASP Juice Shop. Load a
        findings JSON to compute per-class precision/recall.
      </p>

      <div className="lh-eval-cards">
        <div className="lh-eval-card">
          <strong>33.3%</strong>
          <span>Precision</span>
        </div>

        <div className="lh-eval-card">
          <strong>10.0%</strong>
          <span>Recall</span>
        </div>

        <div className="lh-eval-card">
          <strong>15.4%</strong>
          <span>F1-score</span>
        </div>

        <div className="lh-eval-card">
          <strong>1 / 2 / 9</strong>
          <span>TP / FP / FN</span>
        </div>
      </div>

      <h4>Ground-truth composition</h4>

      <div className="lh-gt-bar">
        {CLASSES.map((c) => (
          <div key={c} className="lh-gt-seg">
            <b>{gtCounts[c]}</b>
            <span>{c}</span>
          </div>
        ))}
      </div>

      <p className="lh-audit-note">
        IDOR is 80% of the benchmark yet 0% of recall under the general prompt.
        The matched TP was <code>routes/order.ts</code> (Numerical).
      </p>

      <div className="lh-eval-load">
        <FileInput
          label="Findings JSON"
          onPick={(e) => readJson(e, setFData)}
        />

        <FileInput
          label="Ground truth JSON (optional)"
          onPick={(e) => readJson(e, setTData)}
        />

        {fData && (
          <button
            className="lh-btn-ghost"
            onClick={() => {
              setFData(null);
              setTData(null);
            }}
          >
            Clear
          </button>
        )}
      </div>

      {pc ? (
        <>
          <h4 style={{ marginTop: 16 }}>
            Per-class results computed from loaded file
          </h4>
          <ClassTable pc={pc} />

          {pc.tech > 0 && (
            <p className="lh-audit-note">
              {pc.tech} finding(s) classified as <i>Technical</i> — outside the
              business-logic ground truth, counted as FP globally.
            </p>
          )}
        </>
      ) : (
        <p className="lh-recent-empty">
          Load a findings JSON to see the per-class table.
        </p>
      )}
    </section>
  );
}

// ===================== AI DISCOVERY =====================

export function AiDiscovery() {
  const [fData, setFData] = useState(null);
  const [tData, setTData] = useState(null);

  const findings = asFindings(fData);
  const truth = asTruth(tData);

  const pc = useMemo(
    () => (findings ? perClass(truth, findings) : null),
    [findings, truth]
  );

  const gtCounts = useMemo(() => {
    const c = {
      IDOR: 0,
      Numerical: 0,
      AuthBypass: 0,
      Logic: 0,
    };

    truth.forEach((g) => {
      if (c[g.class] != null) {
        c[g.class] += 1;
      }
    });

    return c;
  }, [truth]);

  const desc = {
    IDOR: "Missing ownership checks on profiles, baskets, orders, files, exports, reviews.",
    Numerical: "Negative quantities, client-controlled prices, refund / coupon abuse.",
    AuthBypass: "Client-controlled roles / admin flags, weak privilege checks.",
    Logic: "Workflow / state manipulation, business-rule violations.",
  };

  return (
    <section className="lh-panel lh-ai">
      <div className="lh-panel-head">
        <h3>AI Discovery</h3>
        <span className="lh-panel-sub">specialist-agent v2 status</span>
      </div>

      <p className="lh-audit-note">
        Each specialist targets one class. Load a specialist findings JSON to
        record its measured recall.
      </p>

      <div className="lh-specialist-grid">
        {CLASSES.map((c) => {
          const r = pc ? pc.rows[c] : null;
          const measured = !!r;
          const recall = r ? pct(r.tp, r.tp + r.fn) : c === "IDOR" ? "0.0" : "—";

          return (
            <article key={c} className="lh-specialist-card">
              <div className="lh-sp-top">
                <b>{c}</b>
                <span
                  className={`lh-score-pill ${measured ? "pass" : "warn"}`}
                >
                  {measured ? "measured" : "awaiting v2"}
                </span>
              </div>

              <p>{desc[c]}</p>

              <div className="lh-sp-metrics">
                <span>
                  <b>{gtCounts[c]}</b> GT
                </span>
                <span>
                  <b>{measured ? r.tp : "—"}</b> TP
                </span>
                <span>
                  <b>{recall}%</b> recall
                </span>
              </div>
            </article>
          );
        })}
      </div>

      <div className="lh-eval-load">
        <FileInput
          label="Specialist findings JSON"
          onPick={(e) => readJson(e, setFData)}
        />

        <FileInput
          label="Ground truth JSON (optional)"
          onPick={(e) => readJson(e, setTData)}
        />

        {fData && (
          <button
            className="lh-btn-ghost"
            onClick={() => {
              setFData(null);
              setTData(null);
            }}
          >
            Clear
          </button>
        )}
      </div>
    </section>
  );
}

// ===================== RISK ACCEPTANCE =====================

export function RiskAcceptance({ apiUrl }) {
  const [repoFullName, setRepoFullName] = useState("");
  const [branchesText, setBranchesText] = useState("main, develop");
  const [approvedBy, setApprovedBy] = useState("Massimo");
  const [ticket, setTicket] = useState("PFE-SEC-001");
  const [reason, setReason] = useState("");
  const [daysValid, setDaysValid] = useState(30);

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const normalizeRepoInput = (value) => {
    return String(value || "")
      .trim()
      .replace(/^https?:\/\/github\.com\//, "")
      .replace(/^https?:\/\/www\.github\.com\//, "")
      .replace(/^github\.com\//, "")
      .replace(/\.git$/, "")
      .replace(/\/+$/, "")
      .toLowerCase();
  };

  const branches = branchesText
    .split(",")
    .map((branch) => branch.trim())
    .filter(Boolean);

  const generateToken = async () => {
    setError("");
    setResult(null);

    const normalizedRepo = normalizeRepoInput(repoFullName);

    if (!normalizedRepo || !normalizedRepo.includes("/")) {
      setError("Repository must be in owner/repository format.");
      return;
    }

    if (!approvedBy.trim()) {
      setError("Approved by is required.");
      return;
    }

    if (!ticket.trim()) {
      setError("Ticket is required.");
      return;
    }

    if (!reason.trim()) {
      setError("Reason is required.");
      return;
    }

    if (!Number(daysValid) || Number(daysValid) <= 0) {
      setError("Expiration must be a positive number of days.");
      return;
    }

    setLoading(true);

    try {
      const response = await fetch(`${apiUrl}/api/risk-acceptance/generate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          repo_full_name: normalizedRepo,
          branches,
          approved_by: approvedBy.trim(),
          reason: reason.trim(),
          ticket: ticket.trim(),
          days_valid: Number(daysValid),
        }),
      });

      const data = await response.json();

      if (!response.ok || data.status !== "success") {
        throw new Error(data.message || "Token generation failed.");
      }

      setResult(data);
    } catch (e) {
      setError(e.message || "Token generation failed.");
    } finally {
      setLoading(false);
    }
  };

  const copyToken = async () => {
    if (!result?.file_content) {
      return;
    }

    await navigator.clipboard.writeText(result.file_content);
    alert("Token copied to clipboard.");
  };

  const downloadSigFile = () => {
    if (!result?.file_content) {
      return;
    }

    const blob = new Blob([result.file_content + "\n"], {
      type: "text/plain",
    });

    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");

    a.href = url;
    a.download = ".logichound.sig";

    document.body.appendChild(a);
    a.click();
    a.remove();

    window.URL.revokeObjectURL(url);
  };

  const matrix = [
    ["≥ 30", "missing", "Success"],
    ["≥ 30", "invalid", "Success because score passed"],
    ["≥ 30", "valid", "Success"],
    ["< 30", "missing", "Failure"],
    ["< 30", "invalid", "Failure"],
    ["< 30", "valid", "Success with risk acceptance"],
  ];

  return (
    <section className="lh-panel lh-risk">
      <div className="lh-panel-head">
        <h3>Risk acceptance</h3>
        <span className="lh-panel-sub">
          signed non-blocking merge-gate token
        </span>
      </div>

      <div className="lh-risk-warning">
        <strong>This is not a scan bypass.</strong>
        <span>
          LogicHound still scans the code and reports all findings. A valid
          token only changes the final merge-blocking decision when the score is
          below the configured threshold.
        </span>
      </div>

      <div className="lh-risk-layout">
        <div className="lh-risk-form">
          <h4>Generate .logichound.sig</h4>

          <label>
            Repository
            <input
              value={repoFullName}
              onChange={(e) => setRepoFullName(e.target.value)}
              placeholder="owner/repository"
            />
            <small>
              Accepts <code>owner/repo</code> or a GitHub HTTPS URL.
            </small>
          </label>

          <label>
            Branches
            <input
              value={branchesText}
              onChange={(e) => setBranchesText(e.target.value)}
              placeholder="main, develop"
            />
            <small>
              Comma-separated. Use <code>*</code> only if explicitly approved.
            </small>
          </label>

          <div className="lh-risk-two">
            <label>
              Approved by
              <input
                value={approvedBy}
                onChange={(e) => setApprovedBy(e.target.value)}
                placeholder="Massimo"
              />
            </label>

            <label>
              Ticket
              <input
                value={ticket}
                onChange={(e) => setTicket(e.target.value)}
                placeholder="PFE-SEC-001"
              />
            </label>
          </div>

          <label>
            Expiration
            <input
              type="number"
              min="1"
              max="365"
              value={daysValid}
              onChange={(e) => setDaysValid(e.target.value)}
            />
            <small>Number of days. Recommended: short-lived tokens.</small>
          </label>

          <label>
            Reason
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Explain why this risk is accepted temporarily..."
              rows={4}
            />
          </label>

          {error && <div className="lh-risk-error">{error}</div>}

          <button
            className="btn-primary"
            onClick={generateToken}
            disabled={loading}
          >
            {loading ? "Generating..." : "Generate signed token"}
          </button>
        </div>

        <div className="lh-risk-output">
          <h4>Generated token</h4>

          {!result ? (
            <div className="lh-risk-empty">
              No token generated yet. Fill the form and generate a signed
              repository-bound token.
            </div>
          ) : (
            <>
              <div className="lh-risk-success">
                Token generated for <b>{result.repo_full_name}</b>
                <br />
                Branches: <code>{result.branches.join(", ")}</code>
                <br />
                Valid for: <code>{result.days_valid} day(s)</code>
              </div>

              <pre className="lh-risk-token">{result.file_content}</pre>

              <div className="lh-risk-actions">
                <button className="lh-btn-ghost" onClick={copyToken}>
                  Copy token
                </button>

                <button
                  className="btn-primary lh-btn-sm"
                  onClick={downloadSigFile}
                >
                  Download .logichound.sig
                </button>
              </div>

              <div className="lh-risk-instructions">
                <h5>Repository instructions</h5>
                <ol>
                  <li>
                    Create a file named <code>.logichound.sig</code> in the
                    repository root.
                  </li>
                  <li>Paste the generated token into that file.</li>
                  <li>Commit and push the file.</li>
                  <li>
                    LogicHound will still run the full scan, but if the token is
                    valid and the score is below threshold, the merge gate passes
                    in risk-accepted mode.
                  </li>
                </ol>
              </div>
            </>
          )}
        </div>
      </div>

      <h4 style={{ marginTop: 20 }}>Decision matrix</h4>

      <table className="lh-eval-table">
        <thead>
          <tr>
            <th>Score</th>
            <th>Token</th>
            <th>Result</th>
          </tr>
        </thead>

        <tbody>
          {matrix.map((row, i) => (
            <tr key={i}>
              <td>{row[0]}</td>
              <td>{row[1]}</td>
              <td>
                <b>{row[2]}</b>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

// ===================== PULL REQUESTS =====================

export function PullRequests({ apiUrl }) {
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");

  const [q, setQ] = useState("");
  const [gate, setGate] = useState("all");

  const loadPullRequests = useCallback(async () => {
    setLoading(true);
    setErr("");

    try {
      const response = await fetch(
        `${apiUrl.replace(/\/+$/, "")}/pull-requests`
      );

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();

      setRecords(
        Array.isArray(data.pull_requests)
          ? data.pull_requests
          : []
      );
    } catch (error) {
      setErr(error.message || "Could not load pull-request scans.");
      setRecords([]);
    } finally {
      setLoading(false);
    }
  }, [apiUrl]);

  useEffect(() => {
    loadPullRequests();
  }, [loadPullRequests]);

  const gateClass = (status) => {
    const value = String(status || "").toLowerCase();

    if (value === "pass" || value === "success") {
      return "pass";
    }

    if (value === "fail" || value === "failure") {
      return "fail";
    }

    return "warn";
  };

  const formatGate = (status) => {
    const value = String(status || "").toLowerCase();

    if (value === "warning_risk_accepted") {
      return "RISK ACCEPTED";
    }

    if (!value) {
      return "—";
    }

    return value.toUpperCase();
  };

  const shortSha = (sha) => {
    if (!sha) {
      return "—";
    }

    return String(sha).slice(0, 7);
  };

  const filtered = useMemo(() => {
    const needle = q.toLowerCase().trim();

    return records.filter((record) => {
      const gateValue = String(record.gate_status || "").toLowerCase();

      const gateOk =
        gate === "all" ||
        (gate === "pass" && gateValue === "pass") ||
        (gate === "fail" && gateValue === "fail") ||
        (gate === "risk" && gateValue === "warning_risk_accepted");

      const text = [
        record.repository,
        record.pr_number,
        record.pr_title,
        record.source_branch,
        record.target_branch,
        record.sha,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      const searchOk = !needle || text.includes(needle);

      return gateOk && searchOk;
    });
  }, [records, q, gate]);

  const setupFlow = [
    "Configure the GitHub webhook endpoint: /webhook",
    "Enable pull_request events: opened and synchronize",
    "Ensure the worker is running",
    "Require the status check: LogicHound AI Gatekeeper",
    "Open or update a pull request to generate a PR scan record",
  ];

  return (
    <section className="lh-panel lh-pr">
      <div className="lh-panel-head">
        <h3>Pull Requests</h3>
        <span className="lh-panel-sub">
          {loading
            ? "loading…"
            : `${filtered.length} of ${records.length} PR scan${
                records.length === 1 ? "" : "s"
              }`}
        </span>
      </div>

      <p className="lh-audit-note">
        This page shows real pull-request scans stored after GitHub webhook
        analysis. Webhooks alone do not block merges; branch protection must
        require the <code>LogicHound AI Gatekeeper</code> status check.
      </p>

      <div className="lh-audit-toolbar">
        <input
          className="lh-chip-search"
          type="search"
          placeholder="Search repo, PR title, branch, SHA…"
          value={q}
          onChange={(event) => setQ(event.target.value)}
          aria-label="Search pull request scans"
        />

        <div className="lh-chips">
          {[
            ["all", "All"],
            ["pass", "Pass"],
            ["fail", "Fail"],
            ["risk", "Risk accepted"],
          ].map(([key, label]) => (
            <button
              key={key}
              className={`lh-chip ${gate === key ? "active" : ""}`}
              onClick={() => setGate(key)}
            >
              {label}
            </button>
          ))}
        </div>

        <button
          className="lh-btn-ghost lh-btn-sm"
          onClick={loadPullRequests}
        >
          Refresh
        </button>
      </div>

      {loading && (
        <p className="lh-recent-empty">
          Loading pull-request scan records…
        </p>
      )}

      {!loading && err && (
        <p className="lh-recent-empty">
          Could not load pull-request scans ({err}).
        </p>
      )}

      {!loading && !err && filtered.length === 0 && (
        <div className="lh-pr-empty">
          <h4>No pull-request scans stored yet.</h4>

          <p>
            PR records will appear here after a GitHub pull request webhook
            triggers <code>run_pr_analysis_task</code> and the worker saves the
            completed result.
          </p>

          <ol className="lh-flow">
            {setupFlow.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>

          <div className="lh-pr-facts">
            <div>
              <span>Webhook endpoint</span>
              <code>/webhook</code>
            </div>

            <div>
              <span>Required status check</span>
              <code>LogicHound AI Gatekeeper</code>
            </div>

            <div>
              <span>PR events</span>
              <code>opened · synchronize</code>
            </div>
          </div>
        </div>
      )}

      {!loading && !err && filtered.length > 0 && (
        <ul className="lh-pr-list">
          <li className="lh-pr-head">
            <span>Repository</span>
            <span>PR</span>
            <span>Branches</span>
            <span>SHA</span>
            <span>Score</span>
            <span>Gate</span>
            <span>Risk</span>
            <span>Comment</span>
          </li>

          {filtered.map((record) => (
            <li key={record.id} className="lh-pr-row">
              <span className="lh-pr-repo" title={record.repository}>
                {record.repository}
              </span>

              <span>
                #{record.pr_number}
                {record.pr_title && (
                  <small title={record.pr_title}>
                    {record.pr_title}
                  </small>
                )}
              </span>

              <span className="lh-pr-branches">
                <code>{record.source_branch || "—"}</code>
                <b>→</b>
                <code>{record.target_branch || "—"}</code>
              </span>

              <span>
                <code>{shortSha(record.sha)}</code>
              </span>

              <span className="lh-audit-score">
                {Math.round(Number(record.score ?? 0))}
              </span>

              <span>
                <span className={`lh-score-pill ${gateClass(record.gate_status)}`}>
                  {formatGate(record.gate_status)}
                </span>
              </span>

              <span>
                {record.risk_accepted ? (
                  <span className="lh-score-pill warn">YES</span>
                ) : (
                  <span className="lh-score-pill pass">NO</span>
                )}
              </span>

              <span>
                {record.comment_url ? (
                  <a
                    href={record.comment_url}
                    target="_blank"
                    rel="noreferrer"
                    className="lh-pr-link"
                  >
                    Open
                  </a>
                ) : (
                  "—"
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
