"""Smart Energy Advisor — Flask app (every file of the project is Python).

The page itself (HTML, CSS and the browser script) is stored in the ui/ modules and served from here.
Python does the real work: accounts (hashed passwords + SQLite), CSV/photo reading, forecasting,
anomaly detection, the what-if simulator, OCR and the Watt chatbot. The browser only shows the UI.

Run:   python app.py        (then open http://127.0.0.1:5000)
"""
import hmac
import json
import os
import re
import secrets
import time
from datetime import timedelta

from flask import Flask, Response, g, jsonify, request, session
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

import db
import ui
from modules import chatbot, ocr_extractor, enterprise, dataset_detection, data_profiling
from modules.common import APPLIANCE_NAMES, month_label
from modules.dashboard import build_dashboard, simulator_shares
from modules.forecasting import forecast_next_month, what_if
from modules.preprocessing import parse_csv_bytes, rows_to_csv, validate_entry
from modules.sample_data import sample_rows

EMAIL_RE = re.compile(r"^\S+@\S+\.\S+$")
MAX_UPLOAD = 6 * 1024 * 1024          # hard limit for any request body
MAX_CSV = 5 * 1024 * 1024
GUEST_TTL = 3 * 24 * 3600             # guest data is deleted after 3 days
ENTRY_SOURCES = {"Manual entry", "Bill photo"}
CSP = ("default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'self'; form-action 'self'")


class ApiError(Exception):
    def __init__(self, status, message, **extra):
        super().__init__(message)
        self.status, self.message, self.extra = status, message, extra


def _secret_key(instance_path):
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(instance_path, "secret.key")
    if not os.path.exists(path):
        with open(path, "w") as fh:
            fh.write(secrets.token_hex(32))
        os.chmod(path, 0o600)
    with open(path) as fh:
        return fh.read().strip()


def create_app(test_config=None):
    app = Flask(__name__, static_folder=None)      # no static files: the UI lives in the ui/ Python modules
    os.makedirs(app.instance_path, exist_ok=True)
    app.config.update(
        DATABASE=os.path.join(app.instance_path, "app.db"),
        SECRET_KEY=_secret_key(app.instance_path),
        MAX_CONTENT_LENGTH=MAX_UPLOAD,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SEA_HTTPS") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(days=14),
    )
    if test_config:
        app.config.update(test_config)
    db.init_db(app.config["DATABASE"])
    attempts: dict[str, list[float]] = {}

    # ---- plumbing --------------------------------------------------------------------------------
    def conn():
        if "db" not in g:
            g.db = db.connect(app.config["DATABASE"])
        return g.db

    @app.teardown_appcontext
    def _close(_exc):
        c = g.pop("db", None)
        if c is not None:
            c.close()

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(24)
        return session["csrf"]

    def owner():
        if "uid" in session:
            return f"u:{session['uid']}"
        if "guest" in session:
            return f"g:{session['guest']}"
        return None

    def need_owner():
        o = owner()
        if not o:
            raise ApiError(401, "Please log in or continue as a guest first.")
        return o

    def me():
        o, user = owner(), None
        if "uid" in session:
            row = db.get_user(conn(), session["uid"])
            if row is None:                       # account vanished: drop the stale session
                session.clear()
                o = None
            else:
                user = {"email": row["email"], "name": row["name"]}
        return {"user": user, "guest": bool(o and o.startswith("g:")),
                "has_data": bool(o and db.dataset(conn(), o)), "csrf": csrf_token()}

    def rows_for(o):
        info = db.dataset(conn(), o)
        if info is None:
            raise ApiError(409, "Add your bill data first.")
        return (sample_rows() if info["sample"] else db.load_rows(conn(), o)), info

    def body():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ApiError(400, "Invalid request.")
        return data

    def throttled(key, limit=8, window=600):
        now = time.time()
        recent = [t for t in attempts.get(key, []) if now - t < window]
        attempts[key] = recent
        return len(recent) >= limit

    def start_session(**values):
        session.clear()
        session.permanent = True
        session.update(values)
        csrf_token()

    @app.before_request
    def _csrf_guard():
        if request.method == "POST" and request.path.startswith("/api/"):
            sent, expected = request.headers.get("X-CSRF-Token", ""), session.get("csrf", "")
            if not expected or not hmac.compare_digest(sent, expected):
                raise ApiError(403, "Your session expired — please refresh the page and try again.")

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Content-Security-Policy", CSP)
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(ApiError)
    def _api_error(e):
        return jsonify(error=e.message, **e.extra), e.status

    @app.errorhandler(HTTPException)
    def _http_error(e):
        if request.path.startswith("/api/"):
            msg = "That file is too large (max 5 MB)." if e.code == 413 else e.description
            return jsonify(error=msg), e.code
        return e

    # ---- pages -----------------------------------------------------------------------------------
    @app.get("/")
    def index():
        return Response(ui.render_index(), mimetype="text/html")

    def asset(text, mimetype):
        resp = Response(text, mimetype=mimetype)
        resp.headers["Cache-Control"] = "public, max-age=3600"
        resp.add_etag()
        return resp.make_conditional(request)

    @app.get("/enterprise")
    def enterprise_page():
        # A separate organization-level prototype; existing household pages remain unchanged.
        page = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Smart Energy Advisor | Enterprise</title><style>
*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:#182230;font:15px/1.5 Arial,sans-serif}
main{max-width:1120px;margin:36px auto;padding:0 18px}.hero{background:#102a43;color:white;padding:28px;border-radius:18px}
.hero p{color:#d9e7f3;margin-bottom:0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin:18px 0}
.card{background:white;border:1px solid #e2e8f0;border-radius:14px;padding:18px}.metric{font-size:27px;font-weight:700;margin-top:6px}
button{border:0;background:#087e6b;color:white;padding:11px 16px;border-radius:9px;font-weight:700;cursor:pointer;margin:5px 6px 5px 0}
button.secondary{background:#e7eef5;color:#203449}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid #e8edf2}th{color:#536579;font-size:12px;text-transform:uppercase}
.pill{display:inline-block;background:#e8f5f1;color:#086653;padding:3px 8px;border-radius:20px;font-size:12px}.muted{color:#64748b}.error{color:#b42318;white-space:pre-wrap}
.section{margin-top:20px}.rec{border-left:4px solid #0b8f78;padding:10px 14px;background:white;border-radius:8px;margin:9px 0}
.vizgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin-top:14px}.vizcard{min-width:0;border:1px solid #e7edf3;border-radius:12px;padding:14px;background:#fbfdff}.vizcard h3{font-size:15px;margin:0 0 8px}.vizcard svg{width:100%;height:auto;display:block;overflow:visible}.axis{stroke:#dbe4ec;stroke-width:1}.barlabel{font:12px Arial;fill:#34465a}.chartlabel{font:12px Arial;fill:#607286}.chartvalue{font:12px Arial;fill:#182230;font-weight:700}.trendline{fill:none;stroke:#087e6b;stroke-width:3;stroke-linecap:round;stroke-linejoin:round}.trenddot{fill:#087e6b;stroke:white;stroke-width:2}
@media(max-width:760px){.vizgrid{grid-template-columns:1fr}}@media(max-width:600px){main{margin:18px auto}.hero{padding:20px}table{font-size:13px}}
</style></head><body><main>
<section class="hero"><div class="pill">ENTERPRISE EDITION · PROTOTYPE</div><h1>Smart Energy Advisor</h1>
<p>Analyze electricity consumption across buildings and departments in schools, colleges, offices and factories.</p></section>
<div class="section card"><h2>Automatic CSV detection</h2><p class="muted">Upload an energy CSV. Smart Energy Advisor identifies the organization type, validates the columns and routes it to the matching analysis.</p>
<input id="csvfile" type="file" accept=".csv,text/csv"><button id="uploadcsv">Detect and analyze CSV</button><div id="detection"></div><div id="status" class="muted"></div></div>
<div id="results" hidden><div class="grid" id="metrics"></div>
<section class="card section"><h2>Energy consumption visualisations</h2><p class="muted">Charts are generated from the uploaded CSV data.</p>
<div class="vizgrid">
<div class="vizcard"><h3>Latest consumption by department</h3><svg id="deptChart" viewBox="0 0 720 330" role="img" aria-label="Horizontal bar chart of latest department consumption"></svg></div>
<div class="vizcard"><h3>Monthly energy consumption trend</h3><svg id="trendChart" viewBox="0 0 720 330" role="img" aria-label="Line chart of total monthly energy consumption"></svg></div>
<div class="vizcard"><h3>Consumption cluster distribution</h3><svg id="clusterChart" viewBox="0 0 720 280" role="img" aria-label="Bar chart showing low, medium and high consumption departments"></svg></div>
<div class="vizcard"><h3>Average vs latest consumption</h3><svg id="compareChart" viewBox="0 0 720 330" role="img" aria-label="Comparison of average and latest department consumption"></svg></div>
</div></section>
<section class="card section"><h2>Department analysis</h2><div style="overflow:auto"><table><thead><tr><th>Department</th><th>Latest units</th><th>Avg. units</th><th>Next-month estimate</th><th>Usage group</th><th>After-hours</th></tr></thead><tbody id="departments"></tbody></table></div></section>
<section class="card section"><h2>Alerts</h2><div id="alerts"></div></section><section class="card section"><h2>Personalized recommendations</h2><p class="muted">Each recommendation shows the data signal that triggered it.</p><div id="recommendations"></div></section><section class="card section"><h2>Method notes</h2><ul id="notes"></ul></section></div>
<script>
const status=document.getElementById('status');
try{const saved=sessionStorage.getItem('sea_enterprise_analysis');if(saved){render(JSON.parse(saved));status.textContent=(sessionStorage.getItem('sea_enterprise_type')||'Organization')+' dataset detected, validated and analyzed.';sessionStorage.removeItem('sea_enterprise_analysis');sessionStorage.removeItem('sea_enterprise_type');}}catch(e){status.textContent='Could not restore the uploaded analysis. Please upload the CSV again.';}
document.getElementById('uploadcsv').onclick=async()=>{const f=document.getElementById('csvfile').files[0];if(!f){status.textContent='Choose a CSV file first.';return;}status.textContent='Detecting dataset and validating rows…';try{const me=await fetch('/api/me').then(r=>r.json());const fd=new FormData();fd.append('file',f);const confirmType=document.getElementById('confirmtype');if(confirmType)fd.append('confirm_type',confirmType.value);const res=await fetch('/api/upload/auto',{method:'POST',headers:{'X-CSRF-Token':me.csrf},body:fd});const d=await res.json();if(!res.ok){if(d.detection){const x=d.detection;document.getElementById('detection').innerHTML=`<div class=\"card section\"><b>Detected: ${esc(x.dataset_label)}</b><p>Heuristic confidence: ${x.confidence}/99</p><p>Data quality: ${x.data_quality?.quality_score??'—'}/100</p><p>${esc(d.error||'Please review this dataset.')}</p><label for=\"confirmtype\">Confirm dataset type</label> <select id=\"confirmtype\"><option value=\"${esc(x.dataset_type)}\">${esc(x.dataset_label)}</option><option value=\"college\">College</option><option value=\"school\">School</option><option value=\"hospital\">Hospital</option><option value=\"factory\">Factory</option><option value=\"office\">Office</option><option value=\"other_organization\">Other organization</option><option value=\"household\">Household</option></select><p class=\"muted\">Choose the correct type, then click Detect and analyze CSV again.</p></div>`;}throw new Error(d.error||'Upload failed');}document.getElementById('detection').innerHTML=`<div class="card section"><b>Detected: ${esc(d.dataset_label)}</b><p>Heuristic confidence: ${d.confidence}/99</p><p>Data quality score: ${d.data_quality.quality_score}/100</p><p>Profile: ${d.data_quality.rows} rows × ${d.data_quality.columns} columns · ${d.data_quality.missing_cells} missing cells · ${d.data_quality.duplicate_rows} duplicate rows</p><p>Validation: ${d.validation.rows} rows valid</p><p>Quality notes: ${(d.data_quality.issues||[]).map(esc).join('; ')||'No quality issues detected'}</p><p>Evidence: ${d.evidence.map(esc).join(', ')||'Column structure'}</p></div>`;if(d.route==='household_dashboard'){status.textContent='Household dataset detected. Opening household dashboard…';location.href=d.dashboard_url;return;}render(d.analysis);status.textContent=`${d.dataset_label} dataset detected and analyzed successfully.`;}catch(e){status.textContent=e.message;status.className='error';}};
function render(d){document.getElementById('results').hidden=false;const m=d.summary;document.getElementById('metrics').innerHTML=[['Departments',m.departments],['Latest total consumption',m.latest_total_units+' units'],['Latest estimated cost','₹'+m.latest_total_amount.toLocaleString('en-IN')],['Records analyzed',d.records_analyzed]].map(x=>`<div class="card"><div class="muted">${x[0]}</div><div class="metric">${x[1]}</div></div>`).join('');
document.getElementById('departments').innerHTML=d.departments.map(x=>`<tr><td>${esc(x.department)}</td><td>${x.latest_units}</td><td>${x.average_units}</td><td>${x.forecast_next_month_units??'Need 3+ months'}</td><td><span class="pill">${esc(x.consumption_group)}</span></td><td>${x.after_hours_share_pct}%</td></tr>`).join('');
drawDepartmentChart(d);drawTrendChart(d);drawClusterChart(d);drawCompareChart(d);
document.getElementById('alerts').innerHTML=d.alerts.length?d.alerts.map(x=>`<div class="rec">${esc(x.message)}</div>`).join(''):'<p class="muted">No month-to-month anomaly met the configured threshold.</p>';
document.getElementById('recommendations').innerHTML=d.recommendations.length?d.recommendations.map(x=>`<div class="rec"><b>${esc(x.target)} · ${esc(x.basis)}</b> <span class="pill">${esc(x.priority)}</span><div>${esc(x.recommendation)}</div></div>`).join(''):'<p class="muted">No recommendations generated from the supplied data.</p>';
document.getElementById('notes').innerHTML=d.method_notes.map(x=>`<li>${esc(x)}</li>`).join('')}
function svgText(x,y,t,cls='chartlabel',anchor='start'){return `<text x="${x}" y="${y}" class="${cls}" text-anchor="${anchor}">${esc(t)}</text>`}
function drawDepartmentChart(d){const el=document.getElementById('deptChart'),items=d.departments.slice(0,9),max=Math.max(1,...items.map(x=>x.latest_units));let s='';items.forEach((x,i)=>{const y=28+i*32,w=470*x.latest_units/max;s+=svgText(4,y+14,x.department.length>19?x.department.slice(0,18)+'…':x.department,'barlabel');s+=`<rect x="205" y="${y}" width="${w}" height="19" rx="5" fill="#168675"/>`;s+=svgText(212+w,y+14,Number(x.latest_units).toLocaleString(),'chartvalue')});el.innerHTML=s||svgText(20,40,'No department data');}
function drawTrendChart(d){const el=document.getElementById('trendChart'),months={};d.departments.forEach(dep=>(dep.history||[]).forEach(r=>months[r.month]=(months[r.month]||0)+r.units));const entries=Object.entries(months).sort((a,b)=>a[0].localeCompare(b[0]));if(!entries.length){el.innerHTML=svgText(20,40,'No monthly history available');return;}const vals=entries.map(x=>x[1]),max=Math.max(1,...vals),min=Math.min(0,...vals),pts=vals.map((v,i)=>[38+(i*(640/Math.max(1,vals.length-1))),260-((v-min)/(max-min||1))*215]);let s='<line x1="38" y1="260" x2="682" y2="260" class="axis"/><line x1="38" y1="35" x2="38" y2="260" class="axis"/>';s+=`<polyline class="trendline" points="${pts.map(p=>p.join(',')).join(' ')}"/>`;pts.forEach((p,i)=>{s+=`<circle class="trenddot" cx="${p[0]}" cy="${p[1]}" r="4"/>`;if(i===0||i===pts.length-1||i%Math.ceil(pts.length/5)===0)s+=svgText(p[0],282,entries[i][0],'chartlabel','middle')});s+=svgText(38,20,'Total units','chartlabel');el.innerHTML=s;}
function drawClusterChart(d){const el=document.getElementById('clusterChart'),names=['Low consumption','Medium consumption','High consumption'],counts=names.map(n=>d.clusters.filter(x=>x.group===n).length),max=Math.max(1,...counts);let s='';names.forEach((n,i)=>{const y=40+i*68,w=470*counts[i]/max;s+=svgText(5,y+17,n,'barlabel');s+=`<rect x="205" y="${y}" width="${w}" height="27" rx="6" fill="#4d83b7"/>`;s+=svgText(214+w,y+18,String(counts[i]),'chartvalue')});el.innerHTML=s;}
function drawCompareChart(d){const el=document.getElementById('compareChart'),items=d.departments.slice(0,6),max=Math.max(1,...items.flatMap(x=>[x.average_units,x.latest_units]));let s='';items.forEach((x,i)=>{const y=25+i*48,w1=430*x.average_units/max,w2=430*x.latest_units/max;s+=svgText(4,y+13,x.department.length>17?x.department.slice(0,16)+'…':x.department,'barlabel');s+=`<rect x="190" y="${y}" width="${w1}" height="13" rx="4" fill="#9bb5cc"/><rect x="190" y="${y+16}" width="${w2}" height="13" rx="4" fill="#168675"/>`;s+=svgText(198+Math.max(w1,w2),y+24,'','chartvalue')});s+=svgText(190,320,'Average (grey)   Latest month (green)','chartlabel');el.innerHTML=s;}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
</script></main></body></html>'''
        resp = Response(page, mimetype="text/html")
        # This standalone prototype page uses its own inline browser script.
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        return resp

    @app.get("/assets/app.css")
    def asset_css():
        return asset(ui.CSS, "text/css")

    @app.get("/assets/app.js")
    def asset_js():
        return asset(ui.JS, "text/javascript")

    @app.get("/favicon.ico")
    def favicon():
        return Response(status=204)

    # ---- accounts --------------------------------------------------------------------------------
    def credentials():
        data = body()
        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", ""))
        if not EMAIL_RE.match(email) or len(email) > 254:
            raise ApiError(400, "Please enter a valid email address.")
        if len(password) < 6:
            raise ApiError(400, "Password must be at least 6 characters.")
        if len(password) > 200:
            raise ApiError(400, "That password is too long.")
        return email, password, str(data.get("name", "")).strip()[:80]

    def log_in(user_id):
        guest = session.get("guest")
        start_session(uid=user_id)
        if guest:                                   # keep what they added as a guest
            db.move_dataset(conn(), f"g:{guest}", f"u:{user_id}")

    @app.get("/api/me")
    def api_me():
        return jsonify(me())

    @app.post("/api/signup")
    def api_signup():
        email, password, name = credentials()
        if db.find_user(conn(), email):
            raise ApiError(409, "An account with this email already exists. Try logging in.")
        try:
            uid = db.create_user(conn(), email, name, generate_password_hash(password))
        except Exception:
            raise ApiError(409, "An account with this email already exists. Try logging in.")
        log_in(uid)
        return jsonify(me())

    @app.post("/api/login")
    def api_login():
        email, password, _ = credentials()
        key = f"{request.remote_addr}|{email}"
        if throttled(key):
            raise ApiError(429, "Too many attempts. Please wait a few minutes and try again.")
        user = db.find_user(conn(), email)
        if not user or not check_password_hash(user["pw_hash"], password):
            attempts.setdefault(key, []).append(time.time())
            raise ApiError(401, "Wrong email or password.")
        log_in(user["id"])
        return jsonify(me())

    @app.post("/api/guest")
    def api_guest():
        db.purge_guests(conn(), GUEST_TTL)
        start_session(guest=secrets.token_urlsafe(16))
        return jsonify(me())

    @app.post("/api/logout")
    def api_logout():
        session.clear()
        return jsonify(me())

    # ---- data in ---------------------------------------------------------------------------------
    @app.post("/api/upload/auto")
    def api_upload_auto():
        """Detect uploaded CSV type, validate it, then route to household or organization analysis."""
        need_owner()
        f = request.files.get("file")
        if f is None or not f.filename:
            raise ApiError(400, "Choose a CSV file first.")
        if not f.filename.lower().endswith((".csv", ".txt")):
            raise ApiError(400, "Please upload a .csv file.")
        raw = f.read(MAX_CSV + 1)
        if len(raw) > MAX_CSV:
            raise ApiError(413, "That file is too large (max 5 MB).")
        try:
            detected = dataset_detection.detect_dataset_bytes(raw)
        except ValueError as exc:
            raise ApiError(400, str(exc))
        quality = data_profiling.profile_dataframe(detected["dataframe"])
        result = {k: detected[k] for k in ("dataset_type", "dataset_label", "confidence", "needs_confirmation", "scores", "evidence", "columns")}
        result["data_quality"] = quality
        source = re.sub(r"[\x00-\x1f]", "", os.path.basename(f.filename))[:80] or "Uploaded CSV"
        confirmed_type = request.form.get("confirm_type", "").strip()
        allowed_types = {"household", "school", "college", "hospital", "factory", "office", "other_organization"}
        if confirmed_type:
            if confirmed_type not in allowed_types:
                raise ApiError(400, "Please select a valid dataset type.", detection=result)
            detected["dataset_type"] = confirmed_type
            detected["dataset_label"] = {"household":"Household", "school":"School", "college":"College", "hospital":"Hospital", "factory":"Factory", "office":"Office", "other_organization":"Other organization"}[confirmed_type]
            result["dataset_type"] = confirmed_type
            result["dataset_label"] = detected["dataset_label"]
        elif detected["needs_confirmation"]:
            raise ApiError(422, "The CSV structure was recognized, but the organization type is uncertain. Please confirm the dataset type before analysis.", detection=result)
        if detected["dataset_type"] == "unknown":
            raise ApiError(422, "The dataset type could not be identified confidently. Add clear column names or choose a type in the confirmation box.", detection=result)
        if quality["critical_issues"]:
            raise ApiError(422, "The CSV has critical data-quality issues. Correct invalid numeric, negative, or date values before analysis.", detection=result)
        if detected["dataset_type"] == "household":
            try:
                rows, skipped = parse_csv_bytes(raw)
            except ValueError as exc:
                raise ApiError(400, str(exc), detection=result)
            db.replace_rows(conn(), owner(), rows, source)
            result.update(ok=True, route="household_dashboard", dashboard_url="/", months=len(rows), skipped=skipped, source=source,
                          validation={"valid": True, "rows": len(rows), "skipped": skipped})
            return jsonify(result)
        try:
            records = dataset_detection.validate_and_convert_enterprise(detected)
            analysis = enterprise.analyze_enterprise(records)
        except ValueError as exc:
            raise ApiError(400, str(exc), detection=result)
        result.update(ok=True, route="enterprise_dashboard", dashboard_url="/enterprise", source=source,
                      validation={"valid": True, "rows": len(records), "skipped": 0}, analysis=analysis)
        return jsonify(result)

    @app.post("/api/upload/csv")
    def api_upload_csv():
        o = need_owner()
        f = request.files.get("file")
        if f is None or not f.filename:
            raise ApiError(400, "Choose a CSV file first.")
        if not f.filename.lower().endswith((".csv", ".txt")):
            raise ApiError(400, "Please upload a .csv file.")
        data = f.read(MAX_CSV + 1)
        if len(data) > MAX_CSV:
            raise ApiError(413, "That file is too large (max 5 MB).")
        try:
            rows, skipped = parse_csv_bytes(data)
        except ValueError as exc:
            raise ApiError(400, str(exc))
        source = re.sub(r"[\x00-\x1f]", "", os.path.basename(f.filename))[:80] or "Uploaded CSV"
        db.replace_rows(conn(), o, rows, source)
        return jsonify(ok=True, months=len(rows), skipped=skipped, source=source)

    @app.post("/api/bills")
    def api_bills():
        o = need_owner()
        data = body()
        source = data.get("source") if data.get("source") in ENTRY_SOURCES else "Manual entry"
        try:
            row = validate_entry(data.get("month"), data.get("units"), data.get("amount"), data.get("appliances"))
        except ValueError as exc:
            raise ApiError(400, str(exc))
        months = db.upsert_row(conn(), o, row, source)
        return jsonify(ok=True, months=months, month_label=month_label(row["m"]))

    @app.post("/api/sample")
    def api_sample():
        db.replace_rows(conn(), need_owner(), [], "Sample data", sample=True)
        return jsonify(ok=True)

    @app.post("/api/ocr")
    def api_ocr():
        need_owner()
        f = request.files.get("image")
        if f is None or not f.filename:
            raise ApiError(400, "Choose a photo first.")
        try:
            result = ocr_extractor.read_bill(f.read())
        except ocr_extractor.OCRUnavailable as exc:
            raise ApiError(503, str(exc), fallback=True)
        except ValueError as exc:
            raise ApiError(400, str(exc))
        return jsonify(ok=True, found=any(result[k] is not None for k in ("m", "u", "a")), **result)

    @app.get("/api/template.csv")
    def api_template():
        csv_text = rows_to_csv(sample_rows()[-12:])
        return Response(csv_text, mimetype="text/csv",
                        headers={"Content-Disposition": 'attachment; filename="smart_energy_template.csv"'})

    # ---- insights --------------------------------------------------------------------------------
    @app.get("/api/dashboard")
    def api_dashboard():
        rows, info = rows_for(need_owner())
        return jsonify(build_dashboard(rows, info["source"], info["sample"]))

    @app.post("/api/simulate")
    def api_simulate():
        rows, _ = rows_for(need_owner())
        data = body()
        appliance = data.get("appliance")
        try:
            pct = float(data.get("pct"))
        except (TypeError, ValueError):
            raise ApiError(400, "Invalid percentage.")
        if appliance not in APPLIANCE_NAMES or not -100 <= pct <= 100:
            raise ApiError(400, "Invalid simulator input.")
        forecast, shares = forecast_next_month(rows), simulator_shares(rows)
        if not forecast or not shares or appliance not in shares:
            raise ApiError(409, "The simulator needs 3+ months of bills and an appliance split.")
        return jsonify(what_if(forecast, shares[appliance], pct))

    @app.post("/api/enterprise/analyze")
    def api_enterprise_analyze():
        data = body()
        try:
            result = enterprise.analyze_enterprise(data.get("records"))
        except ValueError as exc:
            raise ApiError(400, str(exc))
        return jsonify(result)

    @app.post("/api/chat")
    def api_chat():
        data = body()
        message = str(data.get("message", "")).strip()[:500]
        if not message:
            raise ApiError(400, "Type a question first.")
        o = owner()
        info = db.dataset(conn(), o) if o else None
        rows = (sample_rows() if info and info["sample"] else db.load_rows(conn(), o)) if info else None
        return jsonify(chatbot.reply(message, str(data.get("section", "login")), bool(o), rows))

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)),
            debug=os.environ.get("FLASK_DEBUG") == "1")
