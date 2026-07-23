#!/usr/bin/env python3
"""Generate consistent SVG diagrams for the Recon Hound README."""
import os
import xml.dom.minidom as minidom

OUT = "/home/user/burpaderp/docs/img"
os.makedirs(OUT, exist_ok=True)

# palette
NEU = ("#f1f5f9", "#64748b")      # neutral
PAS = ("#e8f0fe", "#1a56db")      # passive (blue)
ACT = ("#fff1e6", "#c2410c")      # active (orange)
REP = ("#e7f6ec", "#15803d")      # reporting (green)
AI  = ("#f5ecfe", "#7e22ce")      # ai (purple)
INK = "#0f172a"
SUB = "#475569"


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def header(w, h, title):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
        f'font-family="Segoe UI, Helvetica, Arial, sans-serif">'
        f'<defs><marker id="ah" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto" '
        f'markerUnits="strokeWidth"><path d="M0,0 L7,3 L0,6 Z" fill="#64748b"/></marker></defs>'
        f'<rect x="0.5" y="0.5" width="{w-1}" height="{h-1}" rx="12" fill="#ffffff" stroke="#e2e8f0"/>'
        f'<text x="{w/2}" y="30" text-anchor="middle" font-size="18" font-weight="700" fill="{INK}">{esc(title)}</text>'
    )


def box(x, y, w, h, lines, color, ink=INK):
    fill, stroke = color
    out = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="9" fill="{fill}" stroke="{stroke}" stroke-width="1.6"/>']
    spacing = 16
    total = spacing * (len(lines) - 1)
    cy = y + h / 2 - total / 2
    for i, ln in enumerate(lines):
        text, size, weight, col = ln
        out.append(
            f'<text x="{x+w/2}" y="{cy}" text-anchor="middle" dominant-baseline="middle" '
            f'font-size="{size}" font-weight="{weight}" fill="{col}">{esc(text)}</text>'
        )
        cy += spacing
    return "".join(out)


def T(text, size=13, weight=400, col=INK):
    return (text, size, weight, col)


def arrow(x1, y1, x2, y2, dashed=False, label=None, color="#64748b"):
    dash = ' stroke-dasharray="5,4"' if dashed else ""
    s = (f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="1.7" '
         f'marker-end="url(#ah)"{dash}/>')
    if label:
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2 - 7
        s += (f'<rect x="{mx-len(label)*3.4-4}" y="{my-11}" width="{len(label)*6.8+8}" height="16" rx="4" '
              f'fill="#ffffff" opacity="0.9"/>'
              f'<text x="{mx}" y="{my}" text-anchor="middle" font-size="10.5" fill="{SUB}">{esc(label)}</text>')
    return s


def note(x, y, text, w=None):
    return (f'<text x="{x}" y="{y}" font-size="11" fill="{SUB}" font-style="italic">{esc(text)}</text>')


def write(name, svg):
    svg += "</svg>"
    minidom.parseString(svg)  # validate well-formed
    with open(os.path.join(OUT, name), "w") as f:
        f.write(svg)
    print("wrote", name, len(svg), "bytes")


# ---------------------------------------------------------------- 1. architecture
def architecture():
    w, h = 960, 300
    s = header(w, h, "Recon Hound — pipeline overview")
    xs = [20, 210, 400, 590, 780]
    bw, bh, by = 160, 168, 92
    cols = [
        (NEU, [T("In-scope HTTP", 13, 700), T("Burp Montoya", 11, 400, SUB), T("HttpHandler", 11, 400, SUB)]),
        (PAS, [T("Passive engines", 13, 700), T("RegexHound · Discovery", 10.5, 400, SUB),
               T("Reflection · Hygiene", 10.5, 400, SUB), T("Source maps · Profiler", 10.5, 400, SUB),
               T("Response signals", 10.5, 400, SUB)]),
        (PAS, [T("Discovery loop", 13, 700), T("scope-bounded", 10.5, 400, SUB),
               T("same-origin, GET-only", 10.5, 400, SUB), T("deduped, capped", 10.5, 400, SUB)]),
        (ACT, [T("Active engines", 13, 700), T("opt-in, off by default", 10.5, 400, SUB),
               T("SSRF/SSTI/XSS/CRLF", 10.5, 400, SUB), T("Access-ctl · Arjun", 10.5, 400, SUB),
               T("crt.sh · API surface", 10.5, 400, SUB)]),
        (REP, [T("Reporting", 13, 700), T("Suite-tab tables", 10.5, 400, SUB),
               T("Burp audit issues", 10.5, 400, SUB), T("Collaborator OOB", 10.5, 400, SUB)]),
    ]
    for x, (color, lines) in zip(xs, cols):
        s += box(x, by, bw, bh, lines, color)
    cy = by + bh / 2
    for i in range(len(xs) - 1):
        s += arrow(xs[i] + bw, cy, xs[i + 1], cy)
    s += note(20, h - 16, "Passive analysis runs continuously; active testing is a deliberate, per-target opt-in.")
    write("architecture.svg", s)


# ---------------------------------------------------------------- 2. UI tabs mockup
def ui_tabs():
    w, h = 960, 380
    s = header(w, h, "Suite tab — Recon Hound")
    # window frame
    s += f'<rect x="20" y="50" width="{w-40}" height="{h-70}" rx="8" fill="#f8fafc" stroke="#cbd5e1"/>'
    # tab strip
    tabs = ["Findings", "Discovered", "Insertion pts", "XSS reflections",
            "Active tests", "Hosts / IPs", "XSS vectors", "AI analysis"]
    tx = 30
    for i, t in enumerate(tabs):
        tw = len(t) * 7.2 + 18
        sel = (i == 4)
        fill = "#ffffff" if sel else "#e2e8f0"
        stroke = ACT[1] if sel else "#cbd5e1"
        s += f'<rect x="{tx}" y="62" width="{tw}" height="26" rx="6" fill="{fill}" stroke="{stroke}" stroke-width="{1.8 if sel else 1}"/>'
        s += f'<text x="{tx+tw/2}" y="79" text-anchor="middle" font-size="11.5" font-weight="{700 if sel else 400}" fill="{INK if sel else SUB}">{esc(t)}</text>'
        tx += tw + 6
    # control panel
    s += f'<rect x="32" y="100" width="{w-64}" height="86" rx="6" fill="#ffffff" stroke="#e2e8f0"/>'
    opts = ["Auto-loop", "Add to scope", "Same-origin", "Follow redirects", "gf patterns", "Detect reflections"]
    ox = 46
    for o in opts:
        s += f'<rect x="{ox}" y="114" width="12" height="12" rx="2" fill="#e8f0fe" stroke="{PAS[1]}"/>'
        s += f'<path d="M{ox+2},{120} L{ox+5},{123} L{ox+10},{116}" fill="none" stroke="{PAS[1]}" stroke-width="1.6"/>'
        s += f'<text x="{ox+18}" y="124" font-size="11.5" fill="{INK}">{esc(o)}</text>'
        ox += len(o) * 7 + 40
    # active-testing opt-in row (highlighted)
    s += f'<rect x="46" y="140" width="14" height="14" rx="2" fill="#fff" stroke="{ACT[1]}" stroke-width="1.6"/>'
    s += f'<text x="66" y="151" font-size="11.5" font-weight="700" fill="{ACT[1]}">Enable active tests (opt-in — authorized targets only)</text>'
    s += f'<text x="430" y="151" font-size="11.5" fill="{SUB}">crt.sh · Arjun · Collaborator SSRF/SSTI/XSS · access-control</text>'
    s += f'<text x="46" y="175" font-size="11" fill="{SUB}">Status: Running | Queue 12 | Discovered 480 | Findings 23 | Reflections 6 | Active 4 | Assets 91</text>'
    # table
    s += f'<rect x="32" y="198" width="{w-64}" height="150" rx="6" fill="#ffffff" stroke="#e2e8f0"/>'
    cols = ["Severity", "Provider", "Rule", "Location", "Value", "URL"]
    cw = [80, 90, 170, 110, 200, 200]
    cx = 40
    s += f'<rect x="34" y="200" width="{w-68}" height="24" fill="#f1f5f9"/>'
    for c, cwid in zip(cols, cw):
        s += f'<text x="{cx}" y="216" font-size="11.5" font-weight="700" fill="{INK}">{esc(c)}</text>'
        cx += cwid
    rows = [
        ("HIGH", "aws", "AWS secret access key", "response", "wJalr…3n4K", "/static/app.js"),
        ("MEDIUM", "hygiene", "CORS reflects Origin", "response", "ACAO=Origin;creds", "/api/me"),
        ("HIGH", "response", "Possible stack trace", "response", "Traceback (most…", "/debug"),
        ("INFO", "sourcemap", "Source map exposed", "response", "42 files recoverable", "/app.js.map"),
    ]
    ry = 244
    for r in rows:
        cx = 40
        sevcol = {"HIGH": "#b91c1c", "MEDIUM": "#c2410c", "INFO": SUB}.get(r[0], INK)
        for i, (val, cwid) in enumerate(zip(r, cw)):
            col = sevcol if i == 0 else INK
            weight = 700 if i == 0 else 400
            s += f'<text x="{cx}" y="{ry}" font-size="11" font-weight="{weight}" fill="{col}">{esc(val)}</text>'
            cx += cwid
        ry += 26
    write("ui-tabs.svg", s)


# ---------------------------------------------------------------- 3. XSS reflection
def xss_reflection():
    w, h = 960, 300
    s = header(w, h, "Passive reflected-XSS surface mapping")
    s += box(30, 70, 200, 70, [T("Request parameter", 12.5, 700), T('q = rhx"><svg…', 11, 400, SUB)], PAS)
    s += box(30, 180, 200, 78, [T("Response body", 12.5, 700), T('<script>var x=', 10.5, 400, SUB),
                                 T('"…q…";</script>', 10.5, 400, SUB)], PAS)
    s += arrow(130, 140, 130, 180, label="reflected")
    s += box(300, 120, 220, 90, [T("Context classifier", 12.5, 700), T("bounded parser-state scan", 10.5, 400, SUB),
                                  T("→ JS string (double-quoted)", 10.5, 400, PAS[1])], NEU)
    s += arrow(230, 219, 300, 175)
    s += box(590, 70, 210, 76, [T("Surviving chars", 12.5, 700), T('" < > ( ) ; =', 12, 700, ACT[1]),
                                T("unencoded at the sink", 10, 400, SUB)], NEU)
    s += box(590, 176, 210, 90, [T("XssVectorLibrary", 12.5, 700), T("suggests viable vectors:", 10, 400, SUB),
                                 T('";alert(document.domain)//', 10.5, 400, AI[1])], AI)
    s += arrow(520, 150, 590, 110)
    s += arrow(520, 170, 590, 205)
    s += note(30, h - 14, "Passive: observes only values the target already returned — nothing is injected.")
    write("xss-reflection.svg", s)


# ---------------------------------------------------------------- 4. passive intel
def passive_intel():
    w, h = 960, 280
    s = header(w, h, "Passive intelligence — hygiene · source maps · API surface")
    cards = [
        (30, PAS, [T("Web hygiene", 13, 700), T("CORS: Origin reflected", 10.5, 400, SUB),
                   T("  + credentials → HIGH", 10.5, 400, ACT[1]), T("CSP: unsafe-inline", 10.5, 400, SUB),
                   T("JWT: alg:none / HS256", 10.5, 400, SUB)]),
        (330, PAS, [T("Source-map mining", 13, 700), T(".map → sourcesContent", 10.5, 400, SUB),
                    T("recover original .ts/.jsx", 10.5, 400, SUB), T("re-scan for endpoints", 10.5, 400, SUB),
                    T("+ secrets bundle hides", 10.5, 400, PAS[1])]),
        (630, PAS, [T("API surface", 13, 700), T("OpenAPI/Swagger paths", 10.5, 400, SUB),
                    T("→ imported to discovery", 10.5, 400, PAS[1]), T("GraphQL endpoint detect", 10.5, 400, SUB),
                    T("+ on-demand introspection", 10.5, 400, SUB)]),
    ]
    for x, color, lines in cards:
        s += box(x, 70, 300, 160, lines, color)
    s += note(30, h - 14, "All passive; runs on every in-scope response and feeds the same finding + discovery pipeline.")
    write("passive-intel.svg", s)


# ---------------------------------------------------------------- 5. active testing
def active_testing():
    w, h = 960, 340
    s = header(w, h, "Active testing — Collaborator out-of-band (opt-in)")
    s += box(30, 70, 190, 80, [T("ParameterProfiler", 12.5, 700), T("ranks SSRF/SSTI/XSS", 10.5, 400, SUB),
                               T("candidate params", 10.5, 400, SUB)], NEU)
    s += box(280, 70, 190, 80, [T("ActiveTestEngine", 12.5, 700), T("mutates param with", 10.5, 400, SUB),
                                T("payload + collab token", 10.5, 400, ACT[1])], ACT)
    s += box(540, 70, 170, 80, [T("Target", 12.5, 700), T("authorized only", 10.5, 400, SUB)], NEU)
    s += arrow(220, 110, 280, 110)
    s += arrow(470, 110, 540, 110)
    s += box(540, 210, 170, 66, [T("Collaborator", 12.5, 700), T("server", 10.5, 400, SUB)], AI)
    s += arrow(625, 150, 625, 210, dashed=True, label="OOB DNS/HTTP")
    s += box(300, 210, 190, 66, [T("Poller correlates", 12.5, 700), T("customData → param", 10.5, 400, SUB)], NEU)
    s += arrow(540, 243, 490, 243)
    s += box(30, 210, 190, 66, [T("HIGH audit issue", 12.5, 700), T("SSRF / blind XSS / CMDi", 10, 400, REP[1])], REP)
    s += arrow(300, 243, 220, 243)
    s += box(740, 70, 190, 206, [T("Also confirmed inline", 12.5, 700), T("SSTI 7*777=5439", 10.5, 400, ACT[1]),
                                 T("reflected-XSS chars", 10.5, 400, SUB), T("open redirect (Location)", 10.5, 400, SUB),
                                 T("CRLF header inject", 10.5, 400, SUB), T("host-header (OOB)", 10.5, 400, SUB),
                                 T("WAF fingerprint", 10.5, 400, SUB)], NEU)
    write("active-testing.svg", s)


# ---------------------------------------------------------------- 6. access control
def access_control():
    w, h = 960, 300
    s = header(w, h, "Access-control / IDOR testing (Autorize-style)")
    s += box(30, 90, 230, 90, [T("Privileged request", 12.5, 700), T("captured in site map", 10.5, 400, SUB),
                               T("200 OK · 1024 bytes", 11, 400, REP[1])], NEU)
    s += box(30, 200, 230, 78, [T("Replay: alternate identity", 12.5, 700), T("strip auth / low-priv cookie", 10.5, 400, SUB),
                                T("safe methods only", 10.5, 400, ACT[1])], ACT)
    s += arrow(145, 180, 145, 200)
    s += box(340, 130, 180, 90, [T("Compare", 12.5, 700), T("status + length diff", 10.5, 400, SUB)], NEU)
    s += arrow(260, 135, 340, 160)
    s += arrow(260, 235, 340, 195)
    s += box(600, 80, 330, 66, [T("BYPASSED → HIGH", 12.5, 700, "#b91c1c"),
                                T("low-priv identity got the same 200 response", 10.5, 400, SUB)], REP)
    s += box(600, 165, 330, 66, [T("ENFORCED → info", 12.5, 700, REP[1]),
                                 T("401/403 or redirect to login", 10.5, 400, SUB)], NEU)
    s += arrow(520, 155, 600, 113)
    s += arrow(520, 185, 600, 198)
    write("access-control.svg", s)


# ---------------------------------------------------------------- 7. AI analysis
def ai_analysis():
    w, h = 960, 340
    s = header(w, h, "AI analysis — manual, multi-provider")
    # context menu mockup
    s += f'<rect x="30" y="70" width="250" height="150" rx="6" fill="#ffffff" stroke="#cbd5e1"/>'
    s += f'<text x="42" y="90" font-size="11.5" font-weight="700" fill="{AI[1]}">Recon Hound: AI analysis</text>'
    items = ["Analyze selected text", "Selected text: chaining", "Explain req/resp & surface",
             "Find vulnerabilities", "Suggest exploitation & chaining"]
    iy = 110
    for it in items:
        s += f'<text x="50" y="{iy}" font-size="11" fill="{INK}">{esc(it)}</text>'
        iy += 22
    s += arrow(280, 145, 360, 145, label="send")
    s += box(360, 100, 200, 96, [T("AI analysis tab", 12.5, 700), T("provider · model", 10.5, 400, SUB),
                                 T("key: field or $ENV", 10.5, 400, SUB), T("in-memory, not saved", 10, 400, ACT[1])], AI)
    # providers fan-out
    provs = ["Anthropic (Claude)", "OpenAI", "xAI (Grok)", "Gemini"]
    py = 74
    for p in provs:
        s += box(660, py, 260, 44, [T(p, 12, 700)], NEU)
        s += arrow(560, 148, 660, py + 22, dashed=True)
        py += 56
    s += box(360, 236, 200, 70, [T("Analysis / exploit chains", 12, 700), T("(verify manually)", 10.5, 400, SUB)], REP)
    s += arrow(460, 196, 460, 236)
    s += note(30, h - 12, "Direct HTTPS (not via Burp) — keys never enter proxy history or the secret scanner. Nothing sent until you click.")
    write("ai-analysis.svg", s)


# ---------------------------------------------------------------- 8. reporting
def reporting():
    w, h = 960, 280
    s = header(w, h, "Reporting — where findings surface")
    s += box(360, 110, 220, 80, [T("Finding", 13, 700), T("secret · signal · reflection", 10.5, 400, SUB),
                                 T("active / OOB confirmation", 10.5, 400, SUB)], NEU)
    s += box(30, 70, 250, 60, [T("Suite-tab tables", 12.5, 700), T("Findings · Reflections · Active · Assets", 10, 400, SUB)], PAS)
    s += box(30, 150, 250, 60, [T("Burp audit issues", 12.5, 700), T("Dashboard / Target", 10, 400, SUB)], REP)
    s += box(680, 70, 250, 60, [T("Extension log", 12.5, 700), T("output / error", 10, 400, SUB)], NEU)
    s += box(680, 150, 250, 60, [T("Collaborator OOB", 12.5, 700), T("HIGH issue, async", 10, 400, ACT[1])], ACT)
    s += arrow(360, 135, 280, 100)
    s += arrow(360, 165, 280, 180)
    s += arrow(580, 135, 680, 100)
    s += arrow(580, 165, 680, 180)
    write("reporting.svg", s)


# ---------------------------------------------------------------- 9. hero banner
def hero():
    w, h = 960, 250
    s = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
         f'font-family="Segoe UI, Helvetica, Arial, sans-serif">'
         f'<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
         f'<stop offset="0" stop-color="#f97316"/><stop offset="0.5" stop-color="#db2777"/>'
         f'<stop offset="1" stop-color="#7e22ce"/></linearGradient></defs>'
         f'<rect x="0" y="0" width="{w}" height="{h}" rx="14" fill="#0b1220"/>'
         f'<rect x="0" y="0" width="{w}" height="7" rx="3" fill="url(#g)"/>')
    s += f'<text x="40" y="98" font-size="54" font-weight="800" fill="#f8fafc" letter-spacing="1.5">RECON HOUND</text>'
    s += f'<text x="44" y="130" font-size="15.5" fill="#94a3b8">Offensive recon &amp; vulnerability toolkit for Burp Suite &#8212; Montoya &#183; Java 21</text>'
    s += f'<text x="{w-40}" y="42" text-anchor="end" font-size="12" font-weight="600" fill="#f97316">every finding &#8594; native Burp issues</text>'
    chips = [("Passive engine", PAS), ("Active opt-in", ACT), ("LLM bug-hunt", AI), ("Nuclei + PDCP", AI),
             ("Exploit chaining", AI), ("SCA", PAS), ("JWT attacks", ACT), ("DOM-XSS", PAS),
             ("Subdomain takeover", ACT), ("SARIF / CI", REP)]
    cx, cy = 42, 162
    for label, (_fill, stroke) in chips:
        cw = len(label) * 7.0 + 26
        if cx + cw > w - 40:
            cx = 42
            cy += 34
        s += f'<rect x="{cx}" y="{cy}" width="{cw}" height="27" rx="13" fill="#111c30" stroke="{stroke}" stroke-width="1.5"/>'
        s += f'<text x="{cx+cw/2}" y="{cy+18}" text-anchor="middle" font-size="12" font-weight="600" fill="#e2e8f0">{esc(label)}</text>'
        cx += cw + 10
    write("hero.svg", s)


# ---------------------------------------------------------------- 10. capability map
def capabilities():
    w, h = 960, 452
    s = header(w, h, "Capability map")
    cols = [
        ("DISCOVER", PAS, ["Crawl + redirect chains", "Webpack chunk rebuild", "Source-map mining",
                           "OpenAPI / GraphQL ingest", "crt.sh subdomains", "Arjun param discovery",
                           "Host / IP aggregation"]),
        ("DETECT", PAS, ["Secrets (RegexHound + gf)", "SCA — vulnerable libs", "Reflected-XSS surface",
                         "DOM-XSS source to sink", "CORS / CSP / JWT hygiene", "Disclosure signals",
                         "Exposed source maps"]),
        ("EXPLOIT", ACT, ["SSRF / SSTI / XSS (OOB)", "Access-control / IDOR", "JWT alg:none + forgery",
                          "GraphQL fuzzing", "Subdomain takeover", "Open-redirect / CRLF",
                          "LLM PoC + exploit chains"]),
        ("OPERATE", REP, ["Native Burp issues", "Passive ScanCheck", "SARIF + Markdown export",
                          "Project persistence", "Headless CI scanner", "Multi-LLM analysis",
                          "Nuclei AI templates + PDCP"]),
    ]
    cw = 220
    gap = (w - 40 - cw * 4) / 3
    x = 20
    top = 54
    for title, (fill, stroke), items in cols:
        s += f'<rect x="{x}" y="{top}" width="{cw}" height="34" rx="8" fill="{stroke}"/>'
        s += f'<text x="{x+cw/2}" y="{top+22}" text-anchor="middle" font-size="14" font-weight="800" fill="#ffffff">{esc(title)}</text>'
        iy = top + 44
        for it in items:
            s += f'<rect x="{x}" y="{iy}" width="{cw}" height="42" rx="7" fill="{fill}" stroke="{stroke}" stroke-width="1.2"/>'
            s += f'<text x="{x+12}" y="{iy+25}" font-size="11.5" font-weight="600" fill="{INK}">{esc(it)}</text>'
            iy += 48
        x += cw + gap
    s += note(20, h - 14, "Passive detection runs continuously and via a native ScanCheck; active exploitation is a per-target opt-in.")
    write("capabilities.svg", s)


architecture()
ui_tabs()
xss_reflection()
passive_intel()
active_testing()
access_control()
ai_analysis()
reporting()
hero()
capabilities()
print("done")
