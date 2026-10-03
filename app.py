import os, sqlite3, secrets, html
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, redirect, url_for, session, jsonify, render_template_string

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "campus-shakthi-demo-secret")
DB = os.environ.get("DATABASE_PATH", "campus_shakthi.db")
STUDENT = (os.environ.get("STUDENT_USER","student"), os.environ.get("STUDENT_PASSWORD","student123"))
ADMIN = (os.environ.get("ADMIN_USER","admin"), os.environ.get("ADMIN_PASSWORD","admin123"))
SECURITY = (os.environ.get("SECURITY_USER","security"), os.environ.get("SECURITY_PASSWORD","security123"))

def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def init_db():
    c=db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS reports(
      id INTEGER PRIMARY KEY AUTOINCREMENT, report_id TEXT UNIQUE, category TEXT,
      description TEXT, priority TEXT, latitude REAL, longitude REAL,
      status TEXT DEFAULT 'NEW', admin_note TEXT, security_note TEXT,
      created_at TEXT, forwarded_at TEXT, resolved_at TEXT
    );
    CREATE TABLE IF NOT EXISTS sos(
      id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE, latitude REAL,
      longitude REAL, status TEXT DEFAULT 'ACTIVE', created_at TEXT,
      forwarded_at TEXT, resolved_at TEXT, security_note TEXT
    );
    CREATE TABLE IF NOT EXISTS locations(
      id INTEGER PRIMARY KEY AUTOINCREMENT, latitude REAL, longitude REAL,
      accuracy REAL, created_at TEXT
    );
    """)
    c.commit(); c.close()
init_db()

def page(title, body, role=None):
    nav = ""
    if role:
        nav=f'<aside><b>CAMPUS<br>SHAKTHI</b><a href="{url_for("portal",role=role)}">Dashboard</a><a href="/">Home</a><a href="{url_for("logout",role=role)}">Logout</a></aside>'
    return render_template_string("""<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{title}}</title><style>
*{box-sizing:border-box}body{margin:0;font-family:Inter,Arial;background:#f5f7fb;color:#172033}aside{position:fixed;inset:0 auto 0 0;width:230px;background:#081a35;color:white;padding:28px 18px;display:flex;flex-direction:column;gap:10px}aside b{font-size:22px;letter-spacing:1px;margin-bottom:25px}aside a{color:#dce8ff;text-decoration:none;padding:12px;border-radius:10px}aside a:hover{background:#12325e}.main{margin-left:230px;padding:34px;max-width:1200px}.card{background:white;border:1px solid #e5e9f2;border-radius:18px;padding:22px;margin:14px 0;box-shadow:0 8px 30px #14213d0c}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px}.btn{display:inline-block;border:0;border-radius:10px;padding:12px 17px;background:#1769e0;color:white;text-decoration:none;cursor:pointer;font-weight:700}.danger{background:#d7263d}.success{background:#16834b}.warn{background:#d98500}.muted{color:#68738a}.status{font-weight:800}.map{background:#eaf2ff;border-radius:14px;padding:15px}.sos{font-size:24px;padding:20px;border-radius:16px;background:#d7263d;color:#fff;border:0;font-weight:900;cursor:pointer}input,select,textarea{width:100%;padding:12px;border:1px solid #d7ddea;border-radius:10px;margin:6px 0 14px}label{font-weight:700}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px;border-bottom:1px solid #edf0f5}@media(max-width:700px){aside{position:static;width:auto;flex-direction:row;overflow:auto}.main{margin:0;padding:18px}}
</style></head><body>{{nav|safe}}<main class="main"><h1>{{title}}</h1>{{body|safe}}</main></body></html>""",title=title,body=body,nav=nav)

def login_required(role):
    def deco(fn):
        @wraps(fn)
        def wrap(*a,**kw):
            if not session.get(role): return redirect(url_for("login",role=role))
            return fn(*a,**kw)
        return wrap
    return deco

@app.route("/")
def home():
    return page("CAMPUS SHAKTHI","""<div class="card"><h2>Campus Safety & Emergency Response Platform</h2><p class="muted">Student → Admin → Security → Resolution</p><div class="grid"><a class="btn" href="/student/login">Student Portal</a><a class="btn" href="/admin/login">Admin Portal</a><a class="btn" href="/security/login">Security Portal</a></div></div>""")

@app.route("/<role>/login",methods=["GET","POST"])
def login(role):
    if role not in ("student","admin","security"): return "Not found",404
    if request.method=="POST":
        creds={"student":STUDENT,"admin":ADMIN,"security":SECURITY}[role]
        if (request.form.get("username"),request.form.get("password"))==creds:
            session.clear(); session[role]=True; return redirect(url_for("portal",role=role))
        msg='<p style="color:#d7263d">Invalid credentials.</p>'
    else: msg=""
    return page(role.title()+" Login",f"""<div class="card">{msg}<form method="post"><label>Username</label><input name="username" required><label>Password</label><input name="password" type="password" required><button class="btn">Login</button></form><p class="muted">Demo: {creds[0]} / {creds[1]}</p></div>""")

@app.route("/<role>/logout")
def logout(role):
    session.pop(role,None); return redirect(url_for("login",role=role))

@app.route("/<role>")
@login_required("student")
def student_root(role):
    if role=="student": return redirect(url_for("portal",role="student"))
    return redirect(url_for("portal",role=role))

@app.route("/portal/<role>")
def portal(role):
    if not session.get(role): return redirect(url_for("login",role=role))
    c=db()
    reports=c.execute("SELECT * FROM reports ORDER BY id DESC LIMIT 20").fetchall()
    active_sos=c.execute("SELECT * FROM sos WHERE status IN ('ACTIVE','FORWARDED') ORDER BY id DESC LIMIT 20").fetchall()
    c.close()
    if role=="student":
        cards='''<div class="card"><h2>Emergency SOS</h2><p>Share your current GPS location with Admin.</p><button class="sos" onclick="sendSOS()">🚨 SEND SOS</button><p id="sosmsg"></p></div>
        <div class="card"><h2>Report Incident</h2><form method="post" action="/student/report"><label>Category</label><select name="category"><option>Harassment</option><option>Ragging</option><option>Bullying</option><option>Threat / Violence</option><option>Unsafe Campus Area</option><option>Other</option></select><label>Description</label><textarea name="description" required></textarea><input type="hidden" name="latitude" id="lat"><input type="hidden" name="longitude" id="lng"><button class="btn">Share Location & Submit</button></form></div>
        <div class="card"><h2>My submitted cases</h2>''' + ''.join(f'<p><b>{html.escape(r["report_id"])}</b> — {html.escape(r["category"])} — <span class="status">{html.escape(r["status"])}</span></p>' for r in reports) + '</div>'
        js="""<script>navigator.geolocation?.getCurrentPosition(p=>{lat.value=p.coords.latitude;lng.value=p.coords.longitude});async function sendSOS(){navigator.geolocation.getCurrentPosition(async p=>{let r=await fetch('/student/sos',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({latitude:p.coords.latitude,longitude:p.coords.longitude})});let j=await r.json();sosmsg.textContent=j.message||j.error||'SOS sent';},()=>sosmsg.textContent='Location permission is required for SOS')}</script>"""
        return page("Student Safety Dashboard",cards+js,"student")
    if role=="admin":
        soshtml=''.join(f'''<div class="card"><h3>🚨 SOS {html.escape(s["event_id"])}</h3><p>Location: {s["latitude"]}, {s["longitude"]}</p><p>Status: <b>{s["status"]}</b></p><a class="btn" target="_blank" href="https://www.google.com/maps?q={s["latitude"]},{s["longitude"]}">Open Map</a>{"" if s["status"]!="ACTIVE" else f'<form style="display:inline" method="post" action="/admin/sos/{s["event_id"]}/forward"><button class="btn warn">Forward to Security</button></form>'}</div>''' for s in active_sos if s["status"] in ("ACTIVE","FORWARDED"))
        reps=''.join(f'''<div class="card"><h3>{html.escape(r["report_id"])} · {html.escape(r["category"])}</h3><p>{html.escape(r["description"])}</p><p>Status: <b>{r["status"]}</b> · Priority: <b>{r["priority"]}</b></p><p>GPS: {r["latitude"]}, {r["longitude"]}</p>{f'<form method="post" action="/admin/report/{r["report_id"]}/forward"><button class="btn warn">Forward to Security</button></form>' if r["status"]=="NEW" else ""}<a class="btn" target="_blank" href="https://www.google.com/maps?q={r["latitude"]},{r["longitude"]}">Map</a></div>''' for r in reports)
        alarm='''<div id="alarm" class="card" style="display:none;background:#ffe8eb"><h2>🔊 ACTIVE SOS ALARM</h2><p>Alarm continues until every active SOS is forwarded to Security.</p><button class="btn" onclick="startAudio()">Enable Alarm Sound</button></div>'''
        js="""<script>let ctx;function startAudio(){ctx=ctx||new(window.AudioContext||window.webkitAudioContext)();let o=ctx.createOscillator(),g=ctx.createGain();o.frequency.value=880;g.gain.value=.08;o.connect(g);g.connect(ctx.destination);o.start();setInterval(()=>{o.frequency.value=o.frequency.value==880?660:880},500)}async function poll(){let j=await fetch('/admin/sos/active');alarm.style.display=j.active?'block':'none';if(!j.active&&ctx){await ctx.close();ctx=null}}setInterval(poll,2000);poll();</script>"""
        return page("Admin Emergency Control Center",alarm+"<h2>SOS Queue</h2>"+soshtml+"<h2>Incident Reports</h2>"+reps+js,"admin")
    sec_sos=''.join(f'''<div class="card"><h3>🚨 SOS {s["event_id"]}</h3><p>GPS: {s["latitude"]}, {s["longitude"]}</p><p>Status: <b>{s["status"]}</b></p>{f'<form method="post" action="/security/sos/{s["event_id"]}/resolve"><input name="note" placeholder="Action taken"><button class="btn success">Problem Solved</button></form>' if s["status"]=="FORWARDED" else ""}</div>''' for s in active_sos if s["status"]=="FORWARDED")
    sec_rep=''.join(f'''<div class="card"><h3>{r["report_id"]}</h3><p>{html.escape(r["description"])}</p><p>Status: <b>{r["status"]}</b></p>{f'<form method="post" action="/security/report/{r["report_id"]}/resolve"><input name="note" placeholder="Action taken"><button class="btn success">Problem Solved</button></form>' if r["status"]=="FORWARDED" else ""}</div>''' for r in reports if r["status"]=="FORWARDED")
    return page("Security Response Center", "<h2>Forwarded SOS</h2>"+(sec_sos or '<div class="card">No forwarded SOS.</div>')+"<h2>Forwarded Reports</h2>"+(sec_rep or '<div class="card">No forwarded reports.</div>'),"security")

@app.route("/student/report",methods=["POST"])
@login_required("student")
def student_report():
    lat=request.form.get("latitude") or None; lng=request.form.get("longitude") or None
    text=request.form.get("description",""); priority="Critical" if any(x in text.lower() for x in ["attack","weapon","life threat","fire"]) else "High" if any(x in text.lower() for x in ["threat","violence","harass","ragging"]) else "Medium"
    rid="CS-"+secrets.token_hex(4).upper()
    c=db(); c.execute("INSERT INTO reports(report_id,category,description,priority,latitude,longitude,created_at) VALUES(?,?,?,?,?,?,?)",(rid,request.form.get("category"),text,priority,lat,lng,now())); c.commit(); c.close()
    return page("Report Submitted",f'<div class="card"><h2>✓ {rid}</h2><p>Your incident has been sent to Admin.</p><a class="btn" href="/portal/student">Back to Dashboard</a></div>',"student")

@app.route("/student/sos",methods=["POST"])
@login_required("student")
def student_sos():
    d=request.get_json(silent=True) or {}
    try: lat=float(d["latitude"]); lng=float(d["longitude"])
    except: return jsonify(ok=False,error="Valid GPS coordinates are required"),400
    eid="SOS-"+secrets.token_hex(4).upper(); c=db(); c.execute("INSERT INTO sos(event_id,latitude,longitude,created_at) VALUES(?,?,?,?)",(eid,lat,lng,now())); c.execute("INSERT INTO locations(latitude,longitude,created_at) VALUES(?,?,?)",(lat,lng,now())); c.commit(); c.close()
    return jsonify(ok=True,message=f"SOS {eid} sent to Admin with live location",event_id=eid)

@app.route("/admin/sos/active")
@login_required("admin")
def active_sos():
    c=db(); n=c.execute("SELECT COUNT(*) n FROM sos WHERE status='ACTIVE'").fetchone()["n"]; c.close(); return jsonify(active=n>0,count=n)

@app.route("/admin/sos/<eid>/forward",methods=["POST"])
@login_required("admin")
def forward_sos(eid):
    c=db(); c.execute("UPDATE sos SET status='FORWARDED',forwarded_at=? WHERE event_id=? AND status='ACTIVE'",(now(),eid)); c.commit(); c.close(); return redirect(url_for("portal",role="admin"))

@app.route("/admin/report/<rid>/forward",methods=["POST"])
@login_required("admin")
def forward_report(rid):
    c=db(); c.execute("UPDATE reports SET status='FORWARDED',forwarded_at=? WHERE report_id=? AND status='NEW'",(now(),rid)); c.commit(); c.close(); return redirect(url_for("portal",role="admin"))

@app.route("/security/sos/<eid>/resolve",methods=["POST"])
@login_required("security")
def resolve_sos(eid):
    c=db(); c.execute("UPDATE sos SET status='RESOLVED',security_note=?,resolved_at=? WHERE event_id=? AND status='FORWARDED'",(request.form.get("note",""),now(),eid)); c.commit(); c.close(); return redirect(url_for("portal",role="security"))

@app.route("/security/report/<rid>/resolve",methods=["POST"])
@login_required("security")
def resolve_report(rid):
    c=db(); c.execute("UPDATE reports SET status='RESOLVED',security_note=?,resolved_at=? WHERE report_id=? AND status='FORWARDED'",(request.form.get("note",""),now(),rid)); c.commit(); c.close(); return redirect(url_for("portal",role="security"))

@app.route("/health")
def health(): return jsonify(ok=True,service="CAMPUS SHAKTHI")

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)))
