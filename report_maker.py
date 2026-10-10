#!/usr/bin/env python3
"""
Recon HTML Report Maker
=======================

Usage:
    python3 recon_html.py /path/to/scan-directory
    python3 recon_html.py /path/to/scan-directory -o report.html

The directory is expected to contain the scanner output files. Known names:
    clean_dir.txt
    nuclei_scan.txt
    param.txt
    portscan.txt
    web_finger.txt

It also recognizes optional files by common names for:
    nmap, ffuf, curl, nikto, linkfinder, sslscan, wafw00f,
    nuclei, gf, dalfox, sqlmap, jexboss

Unknown files are not ignored: they are rendered under "Other output".
No network access is performed.
"""

from __future__ import annotations
import argparse, html, json, re
from pathlib import Path
from datetime import datetime

KNOWN = {
    "clean_dir.txt": "Directory / Content Discovery",
    "nuclei_scan.txt": "Nuclei",
    "param.txt": "Parameter Discovery",
    "portscan.txt": "Nmap",
    "web_finger.txt": "Web Fingerprinting",
}

TOOL_ALIASES = {
    "nmap": "Nmap", "portscan": "Nmap",
    "ffuf": "FFUF", "curl": "cURL", "nikto": "Nikto",
    "linkfinder": "LinkFinder", "sslscan": "SSLScan",
    "wafw00f": "WAFW00F", "nuclei": "Nuclei", "gf": "GF",
    "dalfox": "Dalfox", "sqlmap": "SQLMap", "jexboss": "JExBoss",
    "param": "Parameter Discovery", "clean_dir": "Directory / Content Discovery",
    "web_finger": "Web Fingerprinting",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {x:i for i,x in enumerate(SEVERITY_ORDER)}

def esc(s):
    return html.escape(str(s), quote=True)

def clean(s):
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", s).strip()

def tool_from_name(name):
    stem = Path(name).stem.lower().replace("-", "_")
    for key, value in TOOL_ALIASES.items():
        if key in stem:
            return value
    return Path(name).stem.replace("_", " ").title()

def parse_nuclei(text):
    out = {"findings": [], "facts": [], "negative": [], "warnings": []}
    current = None
    for line in text.splitlines():
        s = clean(line)
        if not s:
            continue
        m = re.match(r"\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+(.+)", s)
        if m:
            template, proto, sev, rest = m.groups()
            sev = sev.lower()
            if sev not in SEVERITY_RANK: sev = "info"
            out["findings"].append({
                "severity": sev,
                "title": template,
                "target": rest,
                "evidence": s
            })
        elif "[WRN]" in s:
            # Nuclei template-loading warnings are operational noise, not report findings.
            continue
    # Empty scan sections are useful successful checks.
    for section in re.findall(r"\[([^\]]+ scan)\]", text, re.I):
        pass
    return out

def parse_nmap(text):
    out = {"findings": [], "facts": [], "negative": [], "warnings": []}
    for line in text.splitlines():
        s = clean(line)
        m = re.match(r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?", s)
        if m:
            port, proto, state, service, version = m.groups()
            out["facts"].append({
                "port": f"{port}/{proto}", "state": state,
                "service": service, "version": version or ""
            })
        if "vulscan" in s.lower() or re.search(r"\[(CVE-\d{4}-\d+)\]", s):
            out["warnings"].append(s)
    m = re.search(r"Nmap scan report for\s+(.+)", text)
    if m: out["host"] = m.group(1)
    m = re.search(r"Host is up \(([^)]+)\)", text)
    if m: out["facts"].append({"host_status": "up", "latency": m.group(1)})
    return out

def parse_web_finger(text):
    out = {"findings": [], "facts": [], "negative": [], "warnings": []}
    sections = re.split(r"(?=^\[[^\n\]]+ scan\]\s*$)", text, flags=re.M|re.I)
    for block in sections:
        if not block.strip(): continue
        header = re.match(r"^\[([^\]]+ scan)\]", block.strip())
        name = header.group(1) if header else "Web"
        if re.search(r"\[curl scan\]", block, re.I):
            # HTTP status blocks
            for m in re.finditer(r"HTTP/([0-9.]+)\s+(\d{3})(.*?)(?=\nHTTP/|\n\[/curl scan\]|$)", block, re.S):
                version, status, tail = m.groups()
                headers = {}
                for ln in tail.splitlines():
                    hm = re.match(r"^\s*([A-Za-z0-9-]+):\s*(.*)$", ln)
                    if hm: headers[hm.group(1).lower()] = hm.group(2).strip()
                out["facts"].append({
                    "http": f"HTTP/{version}", "status": status,
                    "location": headers.get("location", ""),
                    "server": headers.get("server", ""),
                    "content_type": headers.get("content-type", ""),
                })
        elif re.search(r"\[nikto scan\]", block, re.I):
            for ln in block.splitlines():
                s = clean(ln)
                if re.search(r"\+\s*\[[0-9]+\]", s):
                    out["findings"].append({
                        "severity": "medium",
                        "title": "Nikto finding",
                        "target": s,
                        "evidence": s
                    })
                elif "No CGI Directories found" in s or "1 host(s) tested" in s:
                    out["facts"].append({"nikto": s.lstrip("+ ").strip()})
        elif re.search(r"\[ssl scan\]", block, re.I):
            for proto, state in re.findall(r"^\s*(SSLv[23]|TLSv[0-9.]+)\s+(enabled|disabled)", block, re.M|re.I):
                out["facts"].append({"protocol": proto, "state": state})
            for ln in block.splitlines():
                s = clean(ln)
                if "not vulnerable" in s.lower() or "Compression disabled" in s:
                    out["negative"].append(s)
            m = re.search(r"Not valid after:\s*(.+)", block)
            if m: out["facts"].append({"certificate_expires": m.group(1).strip()})
        elif re.search(r"\[waf scan\]", block, re.I):
            if re.search(r"No WAF detected", block, re.I):
                out["negative"].append("No WAF detected by WAFW00F")
            m = re.search(r"Number of requests:\s*(\d+)", block)
            if m: out["facts"].append({"waf_requests": m.group(1)})
    return out

def parse_param(text):
    """Parse Arjun/parameter-discovery output as exactly one result per path.

    Arjun prints progress for every chunk. Those progress lines are operational
    noise and must never become findings. A path such as /api, /up or /horizon
    gets one aggregated result only.
    """
    out = {"findings": [], "facts": [], "negative": [], "warnings": []}
    paths = {}
    current = None

    for line in text.splitlines():
        s = clean(line)
        if not s:
            continue

        # Common Arjun path headings: ===== /api =====, /api, Target: /api, etc.
        m = re.match(r"^=+\s*(/[^=\s]+(?:/[^=\s]*)?)\s*=+$", s)
        if m:
            current = m.group(1).strip()
            paths.setdefault(current, {"positive": [], "negative": [], "other": []})
            continue

        if re.search(r"processing chunks?\s*:\s*\d+\s*/\s*\d+", s, re.I):
            continue

        # Some Arjun versions print the path on its own line.
        if re.fullmatch(r"/[A-Za-z0-9._~:@%+\-]+(?:/[A-Za-z0-9._~:@%+\-]*)*", s):
            current = s
            paths.setdefault(current, {"positive": [], "negative": [], "other": []})
            continue

        if current is None:
            # Ignore global progress/header noise until a path is known.
            continue

        bucket = paths.setdefault(current, {"positive": [], "negative": [], "other": []})
        low = s.lower()
        if "no parameters were discovered" in low:
            bucket["negative"].append(s)
        elif "parameter discovery result" in low:
            bucket["other"].append(s)
        elif s.startswith("[+") or s.startswith("[!"):
            # Keep meaningful Arjun output, but never chunk progress.
            bucket["positive"].append(s)

    for path, bucket in paths.items():
        if bucket["positive"]:
            evidence = "\n".join(dict.fromkeys(bucket["positive"]))
            out["findings"].append({
                "severity": "info",
                "title": "Parameter discovery result",
                "target": path,
                "evidence": evidence,
            })
        elif bucket["negative"]:
            out["negative"].append(f"{path}: no parameters discovered")
        else:
            # A path was discovered/processed but Arjun produced no parameter
            # result. Still expose exactly one informational result for the path.
            out["findings"].append({
                "severity": "info",
                "title": "Parameter discovery result",
                "target": path,
                "evidence": "Path processed by Arjun; no parameter result was emitted.",
            })
    return out

def parse_generic(text, tool):
    out = {"findings": [], "facts": [], "negative": [], "warnings": []}
    for line in text.splitlines():
        s = clean(line)
        if not s: continue
        low = s.lower()
        if any(x in low for x in ["no vulnerability", "not vulnerable", "no findings",
                                  "no parameters", "nothing found", "0 findings",
                                  "no waf detected", "not detected"]):
            out["negative"].append(s)
        elif any(x in low for x in ["critical", "high", "medium", "low", "vulnerable",
                                    "injection", "xss", "rce", "ssrf", "lfi", "rfi"]):
            sev = next((x for x in SEVERITY_ORDER if x in low), "info")
            out["findings"].append({"severity": sev, "title": f"{tool} result",
                                     "target": "", "evidence": s})
        elif any(x in low for x in ["[wrn]", "warning"]):
            out["warnings"].append(s)
        else:
            out["facts"].append({"text": s})
    return out

def split_marker_sections(text):
    """Return [(marker_name, body)] for [name]...[/name] blocks."""
    sections = []
    current_name = None
    buf = []
    for line in text.splitlines():
        om = re.match(r"^\s*\[([^\[\]]+)\]\s*$", line)
        cm = re.match(r"^\s*\[/([^\[\]]+)\]\s*$", line, re.I)
        if current_name is None:
            if om:
                current_name = om.group(1).strip()
                buf = []
        else:
            if cm and cm.group(1).strip().lower() == current_name.lower():
                sections.append((current_name, "\n".join(buf).strip()))
                current_name = None
                buf = []
            else:
                buf.append(line)
    if current_name is not None:
        sections.append((current_name, "\n".join(buf).strip()))
    return sections

def parse_arjun(text):
    out = {"findings": [], "facts": [], "negative": [], "warnings": []}
    endpoint = None
    seen = set()
    for line in text.splitlines():
        s = clean(line)
        if not s:
            continue
        m = re.match(r"^=+\s*(/[^=]+?)\s*=+$", s)
        if m:
            endpoint = m.group(1).strip()
        if re.search(r"processing chunks?\s*:\s*\d+\s*/\s*\d+", s, re.I):
            continue
        if "parameter discovery result" in s.lower():
            key = endpoint or "target"
            if key not in seen:
                seen.add(key)
                out["findings"].append({
                    "severity": "info",
                    "title": "Parameter discovery result",
                    "target": key if key != "target" else "",
                    "evidence": s,
                })
        elif "no parameters were discovered" in s.lower():
            out["negative"].append(f"{endpoint or 'Endpoint'}: no parameters discovered")
    return out

def parse_sectioned(name, text):
    """Parse every [section] block independently; filename is only provenance."""
    sections = split_marker_sections(text)
    if not sections:
        return None
    merged = {"findings": [], "facts": [], "negative": [], "warnings": []}
    for section_name, body in sections:
        n = section_name.lower().strip()
        # Detect Arjun by marker name OR by its unmistakable chunk-progress
        # signature. This prevents parameter output from falling into the
        # generic parser and creating one finding per chunk.
        if "arjun" in n or "parameter" in n or re.search(r"processing chunks?\s*:\s*\d+\s*/\s*\d+", body, re.I):
            data = parse_param(body)
        elif "nuclei" in n or n in {"ssl scan", "vulnerability scan", "cves scan", "technologies scan", "exposure scan", "misconfiguration scan"}:
            data = parse_nuclei(body)
        elif "nmap" in n:
            data = parse_nmap(body)
        elif n in {"curl scan", "nikto scan", "ssl scan", "waf scan"}:
            # Reuse the established parsers with a synthetic wrapper.
            data = parse_web_finger(f"[{section_name}]\n{body}\n[/{section_name}]")
        else:
            data = parse_generic(body, section_name)
        for key in merged:
            merged[key].extend(data.get(key, []))
    return merged

def parse_file(name, text):
    sectioned = parse_sectioned(name, text)
    if sectioned is not None:
        return sectioned
    stem = Path(name).stem.lower()
    if stem == "nuclei_scan": return parse_nuclei(text)
    if stem == "portscan": return parse_nmap(text)
    if stem == "web_finger": return parse_web_finger(text)
    if stem == "param": return parse_param(text)
    return parse_generic(text, tool_from_name(name))

def summarize(parsed):
    findings = []
    facts = []
    negative = []
    warnings = []
    for tool, data in parsed:
        for f in data.get("findings", []):
            f["tool"] = tool
            findings.append(f)
        facts.extend((tool, x) for x in data.get("facts", []))
        negative.extend((tool, x) for x in data.get("negative", []))
        warnings.extend((tool, x) for x in data.get("warnings", []))
    findings.sort(key=lambda x: SEVERITY_RANK.get(x.get("severity","info"), 99))
    counts = {s: sum(1 for x in findings if x.get("severity")==s) for s in SEVERITY_ORDER}
    return findings, facts, negative, warnings, counts

CSS = r"""
:root{--bg:#080b12;--panel:#0e131d;--panel2:#111824;--line:#202a38;--text:#e8edf5;--muted:#8d99aa;--accent:#6ea8fe;--good:#39d98a;--warn:#f7c948;--bad:#ff6b7a;--critical:#ff4d6d}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
a{color:var(--accent)}.layout{display:grid;grid-template-columns:250px 1fr;min-height:100vh}.side{position:sticky;top:0;height:100vh;border-right:1px solid var(--line);background:#090d14;padding:24px 16px}.brand{font-weight:800;font-size:18px;letter-spacing:-.3px;margin-bottom:26px}.recon-brand{color:#ff334f}.recon-name{font:900 32px/0.88 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:-2px;text-transform:lowercase;white-space:nowrap}.recon-name span{color:#ff334f}nav a{display:block;padding:10px 12px;border-radius:8px;color:var(--muted);text-decoration:none;margin:3px 0}nav a:hover{background:#121a26;color:var(--text)}
.main{padding:34px;max-width:1500px;width:100%}.top{display:flex;justify-content:space-between;align-items:flex-end;gap:20px;margin-bottom:26px}.eyebrow{color:var(--accent);font-weight:700;text-transform:uppercase;font-size:11px;letter-spacing:1.3px}.title{font-size:32px;letter-spacing:-1px;margin:3px 0}.target-ip{font-size:14px;letter-spacing:0;color:#ff6677;font-weight:700;margin-left:10px;padding:4px 9px;border:1px solid #5a2430;border-radius:7px;background:#1a0d12;vertical-align:middle}.sub{color:var(--muted)}.grid{display:grid;gap:14px}.cards{grid-template-columns:repeat(6,minmax(0,1fr));margin:18px 0 30px}.card,.panel{background:linear-gradient(180deg,var(--panel),#0c1119);border:1px solid var(--line);border-radius:12px}.card{padding:17px}.label{color:var(--muted);font-size:12px}.num{font-size:26px;font-weight:800;margin-top:5px}.critical{color:var(--critical)}.high{color:#ff8b6b}.medium{color:var(--warn)}.low{color:#71c7ff}.info{color:#aab5c6}.good{color:var(--good)}
.two{grid-template-columns:1.25fr .75fr}.panel{padding:20px;margin-bottom:16px}.panel h2{font-size:16px;margin:0 0 15px}.finding{border:1px solid var(--line);background:#0b1018;border-radius:10px;margin:9px 0;overflow:hidden}.finding-head{display:flex;gap:10px;align-items:center;padding:12px 14px}.badge{font-size:10px;text-transform:uppercase;font-weight:800;border-radius:999px;padding:3px 8px;background:#182130}.finding-title{font-weight:700;flex:1}.meta{color:var(--muted);font-size:12px}.finding pre,.raw pre{white-space:pre-wrap;word-break:break-word;margin:0;padding:13px 14px;border-top:1px solid var(--line);color:#b9c4d3;background:#080c12;font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px 9px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.7px}.pill{display:inline-block;border:1px solid var(--line);padding:2px 7px;border-radius:999px;color:var(--muted);font-size:11px}.empty{padding:18px;border:1px dashed var(--line);border-radius:9px;color:var(--muted)}details{border-top:1px solid var(--line);padding:11px 0}summary{cursor:pointer;font-weight:650}.raw{margin-top:10px}.search{width:100%;background:#0a0f17;border:1px solid var(--line);border-radius:8px;padding:10px;color:var(--text);outline:none}.tool{display:flex;justify-content:space-between;gap:12px;padding:12px;border-bottom:1px solid var(--line)}.tool:last-child{border-bottom:0}.footer{color:var(--muted);font-size:12px;padding:20px 0}.okdot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--good);margin-right:7px}
@media(max-width:1050px){.cards{grid-template-columns:repeat(3,1fr)}.two{grid-template-columns:1fr}.layout{grid-template-columns:1fr}.side{position:relative;height:auto;border-right:0;border-bottom:1px solid var(--line)}nav{display:flex;flex-wrap:wrap;gap:4px}nav a{display:inline-block}.main{padding:22px}}
@media(max-width:650px){.cards{grid-template-columns:repeat(2,1fr)}.main{padding:15px}.title{font-size:25px}}
"""

def read_target_metadata(directory):
    result = {"ip": "", "domain": ""}
    path = directory / "target.txt"
    if not path.is_file():
        return result
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        m = re.match(r"^\s*IP\s*=\s*(.*?)\s*$", line, re.I)
        if m:
            result["ip"] = m.group(1).strip().strip('\"\'')
        m = re.match(r"^\s*DOMAIN\s*=\s*(.*?)\s*$", line, re.I)
        if m:
            result["domain"] = m.group(1).strip().strip('\"\'')
    return result

def sanitize_raw_output(text):
    """Hide operational noise that the report intentionally excludes."""
    out = []
    in_nuclei = False
    in_arjun = False
    for line in text.splitlines():
        s = line.strip()
        om = re.match(r"^\[([^\]]+)\]\s*$", s)
        cm = re.match(r"^\[/([^\]]+)\]\s*$", s, re.I)
        if om:
            name = om.group(1).strip().lower()
            in_nuclei = "nuclei" in name or name in {"ssl scan", "vulnerability scan", "cves scan", "technologies scan", "exposure scan", "misconfiguration scan"}
            in_arjun = "arjun" in name
        if cm:
            name = cm.group(1).strip().lower()
            # Keep closing markers, then leave the section mode.
            if in_nuclei and ("nuclei" in name or name in {"ssl scan", "vulnerability scan", "cves scan", "technologies scan", "exposure scan", "misconfiguration scan"}):
                in_nuclei = False
            if in_arjun and "arjun" in name:
                in_arjun = False
            out.append(line)
            continue
        if in_nuclei and "[wrn]" in s.lower():
            continue
        # Arjun emits chunk progress even when the output is unsectioned.
        # It is operational noise everywhere in the report, not evidence.
        if re.search(r"processing chunks?\s*:\s*\d+\s*/\s*\d+", s, re.I):
            continue
        out.append(line)
    return "\n".join(out)

def render_report(directory, files, parsed):
    findings, facts, negative, warnings, counts = summarize(parsed)
    target_meta = read_target_metadata(directory)
    target = target_meta.get("domain") or ""
    for _, data in parsed:
        if data.get("host"):
            target = data["host"]
            break
    if not target:
        # Find the first obvious URL/host from raw content.
        blob = "\n".join(files.values())
        m = re.search(r"https?://([^/\s]+)", blob)
        target = m.group(1) if m else "Recon target"

    total_checks = len(findings) + len(negative)
    risk = "Critical" if counts["critical"] else "High" if counts["high"] else "Medium" if counts["medium"] else "Low" if counts["low"] else "No findings"
    risk_cls = "critical" if counts["critical"] else "high" if counts["high"] else "medium" if counts["medium"] else "low" if counts["low"] else "good"

    tool_rows = []
    for name, text in files.items():
        tool = tool_from_name(name)
        tool_rows.append(f'<div class="tool"><span>{esc(tool)}</span><span class="pill">{len(text.splitlines())} lines</span></div>')

    finding_html = []
    for f in findings:
        sev = f.get("severity","info")
        finding_html.append(f"""
        <article class="finding" data-search="{esc((f.get('title','')+' '+f.get('target','')+' '+f.get('evidence','')+' '+f.get('tool','')).lower())}">
          <div class="finding-head">
            <span class="badge {sev}">{esc(sev)}</span>
            <span class="finding-title">{esc(f.get('title','Finding'))}</span>
            <span class="meta">{esc(f.get('tool',''))}</span>
          </div>
          <div style="padding:0 14px 12px" class="meta">{esc(f.get('target',''))}</div>
          <pre>{esc(f.get('evidence',''))}</pre>
        </article>""")
    findings_html = "".join(finding_html) or '<div class="empty"><span class="okdot"></span>No parsed security findings were reported by the uploaded outputs.</div>'

    facts_rows = []
    for tool, fact in facts[:250]:
        if isinstance(fact, dict):
            vals = " · ".join(f"<b>{esc(k)}</b>: {esc(v)}" for k,v in fact.items() if v != "")
        else:
            vals = esc(fact)
        facts_rows.append(f"<tr><td>{esc(tool)}</td><td>{vals}</td></tr>")
    facts_html = "".join(facts_rows) or '<tr><td colspan="2">No structured facts parsed.</td></tr>'

    neg_html = "".join(f'<li><b>{esc(t)}</b> — {esc(x)}</li>' for t,x in negative[:250])
    if not neg_html: neg_html = '<li>No explicit negative/clean checks were parsed.</li>'

    warning_html = "".join(f'<li><b>{esc(t)}</b> — {esc(x)}</li>' for t,x in warnings[:250])
    if not warning_html: warning_html = '<li>No warnings parsed.</li>'

    raw_sections = []
    for name, text in files.items():
        raw_sections.append(f"""
        <details>
          <summary>{esc(tool_from_name(name))} <span class="pill">{esc(name)}</span></summary>
          <div class="raw"><pre>{esc(sanitize_raw_output(text))}</pre></div>
        </details>""")
    raw_html = "".join(raw_sections)

    generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Recon Report — {esc(target)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="layout">
<aside class="side">
  <div class="brand recon-brand">
    <div class="recon-name"><span>recon</span><br><span>tool</span></div>
  </div>
  <div class="sub" style="margin-bottom:16px">{esc(target)}</div>
  <nav>
    <a href="#overview">Overview</a><a href="#findings">Findings</a>
    <a href="#attack-surface">Attack surface</a><a href="#checks">Checks</a>
    <a href="#raw">Raw output</a>
  </nav>
</aside>
<main class="main">
<section id="overview">
  <div class="top">
    <div><div class="eyebrow">Security reconnaissance report</div><div class="title">{esc(target)} <span class="target-ip">{esc(target_meta.get("ip") or "IP unavailable")}</span></div>
    <div class="sub">Generated {esc(generated)} · {len(files)} input file(s)</div></div>
    <div class="pill">Local parser · no network requests</div>
  </div>
  <div class="panel" style="margin-bottom:14px">
 <div class="statrow">
  <div class="stat"><b>{esc(target_meta.get("domain") or target or "—")}</b><span>Target domain</span></div>
  <div class="stat"><b>{esc(target_meta.get("ip") or "—")}</b><span>Target IP</span></div>
 </div>
</div>

<div class="grid cards">
    <div class="card"><div class="label">Risk</div><div class="num {risk_cls}">{esc(risk)}</div></div>
    <div class="card"><div class="label">Critical</div><div class="num critical">{counts["critical"]}</div></div>
    <div class="card"><div class="label">High</div><div class="num high">{counts["high"]}</div></div>
    <div class="card"><div class="label">Medium</div><div class="num medium">{counts["medium"]}</div></div>
    <div class="card"><div class="label">Low</div><div class="num low">{counts["low"]}</div></div>
    <div class="card"><div class="label">Clean checks</div><div class="num good">{len(negative)}</div></div>
  </div>
</section>

<div class="grid two">
<section id="findings" class="panel">
  <h2>Findings <span class="pill">{len(findings)}</span></h2>
  <input class="search" id="findingSearch" placeholder="Filter findings, targets, evidence or tools…">
  <div id="findingList">{findings_html}</div>
</section>
<section id="checks" class="panel">
  <h2>Clean / negative results <span class="pill">{len(negative)}</span></h2>
  <ul>{neg_html}</ul>
  <h2 style="margin-top:24px">Parser warnings</h2>
  <ul>{warning_html}</ul>
</section>
</div>

<section id="attack-surface" class="panel">
  <h2>Structured attack-surface data</h2>
  <table><thead><tr><th>Source</th><th>Data</th></tr></thead><tbody>{facts_html}</tbody></table>
</section>


<section id="raw" class="panel">
  <h2>Raw scanner output</h2>
  <div class="sub" style="margin-bottom:10px">Original text is preserved for verification. Parsed findings never replace the raw evidence.</div>
  {raw_html}
</section>

<div class="footer">Recon Report Maker · parser-first reporting · generated locally</div>
</main></div>
<script>
const input=document.getElementById('findingSearch');
const items=[...document.querySelectorAll('.finding')];
input?.addEventListener('input',()=>{{
  const q=input.value.toLowerCase().trim();
  items.forEach(x=>x.style.display=(!q||x.dataset.search.includes(q))?'':'none');
}});
</script>
</body></html>"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("directory", help="Directory containing scanner output files")
    ap.add_argument("-o", "--output", default="recon_report.html")
    args = ap.parse_args()
    directory = Path(args.directory)
    if not directory.is_dir():
        raise SystemExit(f"Not a directory: {directory}")

    files = {}
    for p in sorted(directory.iterdir()):
        if p.is_file() and p.suffix.lower() in {".txt", ".log", ".out"} and p.name.lower() != "target.txt":
            files[p.name] = p.read_text(encoding="utf-8", errors="replace")
    if not files:
        raise SystemExit("No .txt/.log/.out scanner files found.")

    parsed = [(tool_from_name(name), parse_file(name, text)) for name, text in files.items()]
    report = render_report(directory, files, parsed)
    Path(args.output).write_text(report, encoding="utf-8")
    print(f"[+] Report written: {args.output}")
    print(f"[+] Parsed files: {len(files)}")
    print(f"[+] Target: {next((d.get('host') for _,d in parsed if d.get('host')), 'auto-detected')}")
    print("[+] No external dependencies required.")

if __name__ == "__main__":
    main()
