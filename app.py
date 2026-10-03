import os, sqlite3, secrets, json, re
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, request, redirect, url_for, session, jsonify, render_template_string, flash, send_from_directory

BASE=Path(__file__).resolve().parent
UPLOADS=BASE/"uploads"; UPLOADS.mkdir(exist_ok=True)
app=Flask(__name__)
app.secret_key=os.environ.get("SECRET_KEY",secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"]=10*1024*1024
DB=os.environ.get("DATABASE_PATH",str(BASE/"campus_shakthi.db"))
USERS={
 "student":(os.environ.get("STUDENT_USER","student"),os.environ.get("STUDENT_PASSWORD","student123")),
 "admin":(os.environ.get("ADMIN_USER","admin"),os.environ.get("ADMIN_PASSWORD","admin123")),
 "security":(os.environ.get("SECURITY_USER","security"),os.environ.get("SECURITY_PASSWORD","security123"))
}
CATEGORIES=["Harassment","Ragging","Bullying","Threat / Violence","Discrimination","Cyberbullying","Substance-related","Unsafe Campus Area","Suspicious Behaviour","Other"]
SEVERITIES=["Low","Medium","High","Critical"]
STATUSES=["Submitted","Under Review","Forwarded","Security Action","Resolved"]

def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def init_db():
    c=db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS reports(
      id INTEGER PRIMARY KEY AUTOINCREMENT, public_id TEXT UNIQUE, tracking_token TEXT UNIQUE,
      category TEXT,title TEXT,description TEXT,location TEXT,incident_date TEXT,severity TEXT,
      priority TEXT,summary TEXT,tags TEXT,evidence_name TEXT,evidence_path TEXT,
      status TEXT DEFAULT 'Submitted',admin_note TEXT,security_note TEXT,
      latitude REAL,longitude REAL,accuracy REAL,created_at TEXT,updated_at TEXT,
      forwarded_at TEXT,resolved_at TEXT
    );
    CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT,public_id TEXT,sender TEXT,message TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT,message TEXT,severity TEXT,audience TEXT,active INTEGER DEFAULT 1,created_at TEXT,report_public_id TEXT,location_snapshot TEXT);
    CREATE TABLE IF NOT EXISTS sos(id INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE,latitude REAL,longitude REAL,status TEXT DEFAULT 'ACTIVE',created_at TEXT,forwarded_at TEXT,resolved_at TEXT,security_note TEXT);
    CREATE TABLE IF NOT EXISTS locations(id INTEGER PRIMARY KEY AUTOINCREMENT,student_label TEXT,latitude REAL,longitude REAL,accuracy REAL,created_at TEXT);
    CREATE TABLE IF NOT EXISTS contacts(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,kind TEXT,phone TEXT,description TEXT,active INTEGER DEFAULT 1);
    CREATE TABLE IF NOT EXISTS services(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,kind TEXT,phone TEXT,description TEXT,active INTEGER DEFAULT 1);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,action TEXT,ref TEXT,details TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS safety_points(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,kind TEXT,location TEXT,description TEXT);
    """)
    # Backward-compatible migration for databases created by earlier releases.
    migrations = {
        "reports": {"student_user":"TEXT","priority":"TEXT","summary":"TEXT","tags":"TEXT","admin_note":"TEXT","security_note":"TEXT","latitude":"REAL","longitude":"REAL","accuracy":"REAL","forwarded_at":"TEXT","resolved_at":"TEXT","updated_at":"TEXT","evidence_name":"TEXT","evidence_path":"TEXT","severity":"TEXT"},
        "alerts": {"report_public_id":"TEXT","location_snapshot":"TEXT"},
        "sos": {"forwarded_at":"TEXT","resolved_at":"TEXT","security_note":"TEXT"},
        "locations": {"accuracy":"REAL"},
        "contacts": {"description":"TEXT","active":"INTEGER DEFAULT 1"},
        "services": {"description":"TEXT","active":"INTEGER DEFAULT 1"}
    }
    for table, cols in migrations.items():
        existing = {row["name"] for row in c.execute("PRAGMA table_info(" + table + ")").fetchall()}
        for col, typ in cols.items():
            if col not in existing:
                c.execute("ALTER TABLE " + table + " ADD COLUMN " + col + " " + typ)
    report_cols = {row["name"] for row in c.execute("PRAGMA table_info(reports)").fetchall()}
    if "ai_priority" in report_cols and "priority" in report_cols:
        c.execute("UPDATE reports SET priority=COALESCE(NULLIF(priority,''),ai_priority)")
    if "ai_summary" in report_cols and "summary" in report_cols:
        c.execute("UPDATE reports SET summary=COALESCE(NULLIF(summary,''),ai_summary)")
    if "ai_tags" in report_cols and "tags" in report_cols:
        c.execute("UPDATE reports SET tags=COALESCE(NULLIF(tags,''),ai_tags)")
    c.commit()
    if c.execute("SELECT COUNT(*) n FROM contacts").fetchone()["n"]==0:
        c.executemany("INSERT INTO contacts(name,kind,phone,description) VALUES(?,?,?,?)",[
          ("Campus Security","Security","+91 99999 99999","24x7 campus security"),
          ("Emergency Services","Emergency","112","National emergency response")])
    if c.execute("SELECT COUNT(*) n FROM services").fetchone()["n"]==0:
        c.executemany("INSERT INTO services(name,kind,phone,description) VALUES(?,?,?,?)",[
          ("Campus Medical Help","Medical","108","Emergency medical assistance"),
          ("Student Helpline","Helpline","+91 99999 88888","Student support and guidance")])
    if c.execute("SELECT COUNT(*) n FROM safety_points").fetchone()["n"]==0:
        c.executemany("INSERT INTO safety_points(name,kind,location,description) VALUES(?,?,?,?)",[
          ("Campus Security Office","Security","Main Gate","Primary response point"),
          ("First Aid Centre","Medical","Student Services Block","First aid and medical support"),
          ("Emergency Assembly Area","Safe Zone","Central Ground","Emergency gathering area"),
          ("Main Gate Emergency Exit","Exit","North Entrance","Primary emergency exit"),
          ("Student Support Desk","Support","Admin Block","Student support and grievance guidance")])
    c.commit(); c.close()
init_db()

def classify_report(cat,title,desc,severity):
    """Deterministic report classification; no external  service is used."""
    priority=severity if severity in SEVERITIES else "Medium"
    tags=[cat]
    text=(cat+" "+title+" "+desc).lower()
    if any(k in text for k in ("hostel","room","dorm")): tags.append("Hostel")
    if any(k in text for k in ("whatsapp","instagram","online","account")): tags.append("Digital")
    if any(k in text for k in ("night","dark","evening")): tags.append("After-hours")
    summary=re.sub(r"\s+"," ",desc).strip()
    return priority,summary[:240],", ".join(dict.fromkeys(tags))

def audit(action,ref="",details=""):
    c=db(); c.execute("INSERT INTO audit(action,ref,details,created_at) VALUES(?,?,?,?)",(action,ref,details,now())); c.commit(); c.close()
def auth(role):
    def deco(fn):
        @wraps(fn)
        def wrapped(*a,**kw):
            if not session.get(role): return redirect(url_for("login",role=role))
            return fn(*a,**kw)
        return wrapped
    return deco

CSS="""""
:root{
 --ink:#071a33;--ink2:#0b2748;--blue:#2563eb;--cyan:#06b6d4;--violet:#7c3aed;
 --green:#16a34a;--red:#ef3340;--amber:#f59e0b;--bg:#eef4fb;--panel:#ffffffd9;
 --line:#dce6f2;--muted:#66758b;--shadow:0 18px 55px rgba(7,30,58,.10)
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:radial-gradient(circle at 80% -10%,#dff4ff 0,#eef4fb 35%,#f6f9fc 70%);color:#10213b;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.35;background-image:linear-gradient(#9fb3c91a 1px,transparent 1px),linear-gradient(90deg,#9fb3c91a 1px,transparent 1px);background-size:42px 42px;mask-image:linear-gradient(to bottom,#000,transparent 75%);z-index:-1}
a{text-decoration:none;color:inherit}button,input,select,textarea{font:inherit}
.shell{display:flex;min-height:100vh}
.side{position:fixed;left:18px;top:18px;bottom:18px;width:248px;background:#071a33f2;color:#fff;border:1px solid #ffffff18;border-radius:24px;padding:18px 13px;z-index:30;overflow:auto;box-shadow:0 24px 70px #06172d30;backdrop-filter:blur(20px)}
.brand{font-weight:950;font-size:18px;letter-spacing:.04em;padding:12px 13px 20px;border-bottom:1px solid #ffffff16;margin-bottom:16px}.brand span{color:#43d5e4}
.navtitle{font-size:9px;font-weight:900;color:#91a5bf;letter-spacing:.18em;margin:18px 10px 8px}
.nav{display:flex;align-items:center;min-height:42px;padding:10px 12px;border-radius:12px;color:#b9c8da;font-size:12px;font-weight:800;margin:4px 0;transition:.2s}
.nav:hover,.nav.active{background:linear-gradient(90deg,#2563eb,#06b6d4);color:#fff;box-shadow:0 10px 25px #2563eb35;transform:translateX(2px)}
.main{margin-left:284px;width:calc(100% - 284px);padding:0 38px 60px}
.top{height:78px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #dce6f2aa;position:sticky;top:0;background:#eef4fbd9;backdrop-filter:blur(18px);z-index:20}
.top>div:first-child{display:flex;flex-direction:column;gap:3px}.top b{font-size:14px}.top small{color:var(--muted);font-size:10px}
.wrap{max-width:1320px;margin:auto}
.hero{padding:68px 0 44px;display:grid;grid-template-columns:1.05fr .95fr;gap:46px;align-items:center}
.eyebrow{font-size:10px;color:var(--blue);font-weight:950;letter-spacing:.18em}
.hero h1{font-size:clamp(44px,6vw,78px);line-height:.94;margin:15px 0 18px;letter-spacing:-.065em;color:#071a33}.hero h1 span{background:linear-gradient(90deg,#2563eb,#06b6d4,#7c3aed);-webkit-background-clip:text;background-clip:text;color:transparent}
.hero p{color:var(--muted);font-size:15px;line-height:1.8;max-width:700px}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:22px}
.btn{border:1px solid var(--line);border-radius:12px;padding:11px 16px;background:#fff;font-weight:850;cursor:pointer;display:inline-flex;justify-content:center;align-items:center;gap:7px;box-shadow:0 7px 18px #18395c0b;transition:.18s}
.btn:hover{transform:translateY(-2px);box-shadow:0 12px 25px #18395c18}.btn.primary{background:linear-gradient(135deg,#2563eb,#06b6d4);color:#fff;border-color:transparent}.btn.danger{background:linear-gradient(135deg,#ef3340,#c51f32);color:#fff;border-color:transparent}.btn.success{background:linear-gradient(135deg,#16a34a,#059669);color:#fff;border-color:transparent}.btn.warn{background:linear-gradient(135deg,#f59e0b,#ea580c);color:#fff;border-color:transparent}.btn.small{padding:8px 11px;font-size:11px}
.card{background:linear-gradient(145deg,#ffffffef,#f9fcffdc);border:1px solid #dce6f2;border-radius:20px;padding:21px;box-shadow:var(--shadow);margin:15px 0;backdrop-filter:blur(12px)}
.card h2,.card h3{color:#0a2140}.grid{display:grid;gap:16px}.g2{grid-template-columns:repeat(2,1fr)}.g3{grid-template-columns:repeat(3,1fr)}.g4{grid-template-columns:repeat(4,1fr)}
.stat{padding:20px;position:relative;overflow:hidden}.stat:after{content:"";position:absolute;width:90px;height:90px;border-radius:50%;right:-35px;top:-35px;background:#2563eb12}.stat span{color:#73839a;font-size:10px;font-weight:900;letter-spacing:.1em}.stat strong{display:block;font-size:34px;margin-top:8px;color:#071a33}
.pagehead{padding:42px 0 18px}.pagehead h1{font-size:43px;margin:7px 0 10px;letter-spacing:-.045em}.muted{color:var(--muted);line-height:1.65}.pill{display:inline-block;padding:5px 9px;border-radius:999px;background:#edf4ff;color:#46617f;font-size:9px;font-weight:950;margin:2px}.critical{color:var(--red)}.high{color:#c36f00}.ok{color:var(--green)}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:11px;border-bottom:1px solid #edf0f5;font-size:12px;vertical-align:top}
.form{display:grid;gap:12px}.form label{font-size:11px;font-weight:850;color:#33465f}.form input,.form textarea,.form select{width:100%;padding:12px 13px;border:1px solid #d5e0ed;border-radius:12px;background:#fbfdff;outline:none;transition:.2s}.form input:focus,.form textarea:focus,.form select:focus{border-color:#5d8ff0;box-shadow:0 0 0 4px #2563eb12}.form textarea{min-height:120px}
.mapbox{background:radial-gradient(circle at 50% 45%,#dff8f1,#eaf3fb 55%,#dfeaf7);border:1px solid #d0deeb;border-radius:18px;min-height:270px;position:relative;overflow:hidden;box-shadow:inset 0 0 40px #5d88ad12}.mapbox:before,.mapbox:after{content:"";position:absolute;background:#c7d7e5;height:14px;width:125%;transform:rotate(-24deg);left:-12%;top:39%;box-shadow:0 36px 0 #d7e3ee}.mapbox:after{transform:rotate(24deg);top:66%}.mapdot{position:absolute;width:15px;height:15px;border-radius:50%;background:var(--red);box-shadow:0 0 0 9px #ef334028,0 0 25px #ef334099;z-index:2;animation:pulse 1.5s infinite}@keyframes pulse{50%{box-shadow:0 0 0 15px #ef334000,0 0 30px #ef334077}}
.alert{padding:15px;border-radius:14px;border:1px solid var(--line);background:#fff}.alert.critical{border-color:#ffc2cb;background:#fff6f7}.sosbox{background:radial-gradient(circle at 50% 30%,#fff,#fff0f3);border:1px solid #ffc7cf}
.sosbtn{width:178px;height:178px;border-radius:50%;border:8px solid #ffffff;color:#fff;font-size:22px;font-weight:950;cursor:pointer;background:radial-gradient(circle at 35% 25%,#ff6670,#ef3340 48%,#b91c2c);box-shadow:0 0 0 12px #ef334018,0 20px 55px #ef334045;animation:sosglow 1.8s infinite}.sosbtn:active{transform:scale(.97)}@keyframes sosglow{50%{box-shadow:0 0 0 24px #ef334000,0 22px 65px #ef334050}}
.alarm{background:linear-gradient(135deg,#fff0f2,#fff);border:2px solid #ff9baa;animation:alarm 1s infinite}.hidden{display:none}@keyframes alarm{50%{box-shadow:0 0 0 9px #ef334014,0 18px 45px #ef33401c}}
.threeD{min-height:400px;border-radius:30px;background:radial-gradient(circle at 50% 35%,#154b73,#07172d 60%);position:relative;overflow:hidden;box-shadow:0 35px 90px #07172d35;border:1px solid #ffffff20;isolation:isolate}.threeD:before{content:"";position:absolute;width:430px;height:430px;border-radius:50%;left:50%;top:50%;transform:translate(-50%,-50%);background:radial-gradient(circle,#28c6e844 0,#1769e012 42%,transparent 70%);filter:blur(2px)}.threeD:after{content:"";position:absolute;inset:20px;border:1px solid #ffffff12;border-radius:25px;transform:perspective(700px) rotateX(58deg);top:52%;height:55%}
.shield{position:absolute;left:50%;top:49%;transform:translate(-50%,-50%);width:145px;height:165px;clip-path:polygon(50% 0,90% 17%,84% 70%,50% 100%,16% 70%,10% 17%);background:linear-gradient(145deg,#52e1e8 0,#2563eb 55%,#5638c8 100%);display:grid;place-items:center;color:#fff;font-size:46px;box-shadow:0 35px 90px #0008;z-index:3}.orb{position:absolute;border:1px solid #53d9e855;border-radius:50%;width:370px;height:145px;left:50%;top:50%;transform:translate(-50%,-50%) rotate(-18deg);box-shadow:0 0 50px #20c5d722}
.float{position:absolute;padding:11px 15px;border:1px solid #ffffff22;background:#ffffff12;color:#fff;border-radius:14px;backdrop-filter:blur(10px);font-weight:850;z-index:4;box-shadow:0 15px 35px #0003;animation:f 4s ease-in-out infinite}.f1{left:7%;top:18%}.f2{right:7%;top:23%;animation-delay:1s}.f3{right:10%;bottom:15%;animation-delay:2s}@keyframes f{50%{transform:translateY(-10px) rotate(1deg)}}
.login{max-width:470px;margin:70px auto}.login .card{padding:32px;border-radius:24px}.footer{text-align:center;color:#8290a3;font-size:10px;padding:25px 0}.kpi{display:flex;justify-content:space-between;align-items:center}.kpi b{font-size:28px}.activity{max-height:380px;overflow:auto}.activity p{padding:10px 0;border-bottom:1px solid #edf0f5;font-size:12px}.case{border:1px solid var(--line);border-radius:16px;padding:17px;background:#ffffffcf;box-shadow:0 8px 25px #17385c08}.case h3{margin:5px 0}.case-actions{display:flex;gap:7px;flex-wrap:wrap;margin-top:12px}.chat{max-height:250px;overflow:auto}.msg{padding:10px;border-radius:10px;background:#f4f7fb;margin:7px 0;font-size:12px}.msg.admin{border-left:3px solid var(--blue)}.msg.security{border-left:3px solid var(--green)}
@media(max-width:1000px){.hero,.g2,.g3,.g4{grid-template-columns:1fr 1fr}.hero{grid-template-columns:1fr}.side{left:10px;width:215px}.main{margin-left:240px;width:calc(100% - 240px);padding:0 22px 50px}}@media(max-width:680px){.side{position:relative;left:0;top:0;bottom:auto;width:100%;height:auto;border-radius:0}.shell{display:block}.main{margin:0;width:100%;padding:0 15px 35px}.top{position:relative}.g2,.g3,.g4{grid-template-columns:1fr}.hero{padding-top:35px}.hero h1{font-size:46px}.pagehead h1{font-size:35px}.threeD{min-height:330px}}
"""

def page(title,body,role=None,active=""):
    nav=""
    if role:
        items=[("Dashboard","portal",role),("Report Incident","report",None),("Track Case","track",None),("Emergency SOS","emergency",None),("Safety Map","safety_map",None),("Resources","resources",None),("Privacy","privacy",None)]
        if role=="admin": items=[("Command Center","portal",role),("Incident Queue","portal",role),("SOS Control","portal",role),("Live Map","portal",role),("Alerts","portal",role),("Contacts & Services","portal",role),("Audit Logs","portal",role)]
        if role=="security": items=[("Security Dashboard","portal",role),("Forwarded Cases","portal",role),("SOS Response","portal",role),("Live Location","portal",role),("Safety Points","portal",role)]
        nav='<div class="side"><div class="brand">CAMPUS <span>SHAKTHI</span></div><div class="navtitle">NAVIGATION</div>'
        for label,route,arg in items:
            href=url_for(route,role=arg) if arg else url_for(route)
            anchors={
"Incident Queue":"incident-queue","SOS Control":"sos-control","Live Map":"live-map",
"Alerts":"alerts","Contacts & Services":"contacts","Audit Logs":"audit",
"Forwarded Cases":"forwarded-cases","SOS Response":"sos-response","Live Location":"live-location","Safety Points":"safety-points"}
            if label in anchors: href += "#" + anchors[label]
            nav_class = "nav active" if active==label else "nav"
            nav+=f'<a class="{nav_class}" href="{href}">{label}</a>'
        nav+=f'<div class="navtitle">ACCOUNT</div><a class="nav" href="{url_for("logout",role=role)}">Logout</a></div>'
    sidebar_script = """<script>document.addEventListener("DOMContentLoaded",function(){var h=location.hash.replace("#","");if(!h)return;var names={"incident-queue":"Incident Queue + Incident Priority","sos-control":"SOS Control Queue","live-map":"Latest Student Location","alerts":"Broadcast Safety Alert","contacts":"Contacts & Services","audit":"Audit Activity","forwarded-cases":"Forwarded Incident Reports","sos-response":"SOS Response Queue","live-location":"Latest Live Location","safety-points":"Campus Safety Points"};var target=names[h];if(!target)return;document.querySelectorAll("h2").forEach(function(el){if(el.textContent.indexOf(target)>=0){el.scrollIntoView({behavior:"smooth",block:"start"});el.parentElement.style.outline="3px solid #2563eb";setTimeout(function(){el.parentElement.style.outline=""},1800);}});});</script>"""
    return f"""<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title} · CAMPUS SHAKTHI</title><style>{CSS}</style></head><body><div class="shell">{nav}<div class="main"><div class="top"><div><b>{title}</b><small>Kalasalingam University Campus Safety Platform</small></div><div><span class="pill">● SYSTEM ONLINE</span></div></div><div class="wrap">{body}</div><div class="footer">CAMPUS SHAKTHI · Student Safety · Admin Response · Security Resolution</div></div></div>{sidebar_script}</body></html>"""


@app.route("/")
def home():
    body=f"""<section class="hero"><div><div class="eyebrow">CAMPUS SAFETY • RESPONSE • RESOLUTION</div><h1>One campus.<br><span>One safety command.</span></h1><p>CAMPUS SHAKTHI connects students, administrators and security in one response workflow with anonymous reporting, severity classification, live location, emergency SOS, alerts, maps, evidence and resolution tracking.</p><div class="actions"><a class="btn primary" href="/student/login">Student Portal</a><a class="btn" href="/admin/login">Admin Command Center</a><a class="btn" href="/security/login">Security Portal</a></div></div><div class="threeD"><div class="orb"></div><div class="shield">🛡</div><div class="float f1">🎓 Student</div><div class="float f2">⚡ Admin</div><div class="float f3">🚓 Security</div></div></section><div class="grid g3"><div class="card"><h3>Anonymous reporting</h3><p class="muted">Submit a case, attach evidence, receive a private tracking token and communicate without exposing identity in the case workflow.</p></div><div class="card"><h3>Emergency SOS</h3><p class="muted">Student GPS is persisted with the SOS. Admin receives the emergency and the continuous alarm remains active until forwarding.</p></div><div class="card"><h3>Security resolution</h3><p class="muted">Admin forwards the exact case and location. Security takes action, records notes and marks the incident resolved.</p></div></div>"""
    return page("CAMPUS SHAKTHI",body)

@app.route("/<role>/login",methods=["GET","POST"])
def login(role):
    if role not in USERS: return "Not found",404
    msg=""
    if request.method=="POST":
        if (request.form.get("username"),request.form.get("password"))==USERS[role]:
            session.clear(); session[role]=True; session["login_user"]=request.form.get("username",""); return redirect(url_for("portal",role=role))
        msg='<div class="alert critical">Invalid credentials.</div>'
    body=f"""<div class="login"><div class="card"><div class="eyebrow">{role.upper()} ACCESS</div><h1>{role.title()} Login</h1>{msg}<form class="form" method="post"><label>Username<input name="username" required></label><label>Password<input name="password" type="password" required></label><button class="btn primary">Sign in</button></form><p class="muted">Demo: <b>{USERS[role][0]}</b> / <b>{USERS[role][1]}</b></p></div></div>"""
    return page(role.title()+" Login",body)

@app.route("/<role>/logout")
def logout(role):
    session.clear()
    return redirect(url_for("home"))

@app.route("/portal/<role>")
def portal(role):
    if role not in USERS: return "Not found",404
    if not session.get(role): return redirect(url_for("login",role=role))
    c=db()
    reports=c.execute("SELECT * FROM reports ORDER BY id DESC LIMIT 50").fetchall()
    sos=c.execute("SELECT * FROM sos ORDER BY id DESC LIMIT 30").fetchall()
    alerts=c.execute("SELECT * FROM alerts WHERE active=1 ORDER BY id DESC LIMIT 15").fetchall()
    contacts=c.execute("SELECT * FROM contacts WHERE active=1 ORDER BY id").fetchall()
    services=c.execute("SELECT * FROM services WHERE active=1 ORDER BY id").fetchall()
    points=c.execute("SELECT * FROM safety_points ORDER BY id").fetchall()
    loc=c.execute("SELECT * FROM locations ORDER BY id DESC LIMIT 1").fetchone()
    logs=c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 30").fetchall()
    total=c.execute("SELECT COUNT(*) n FROM reports").fetchone()["n"]
    critical=c.execute("SELECT COUNT(*) n FROM reports WHERE priority='Critical'").fetchone()["n"]
    open_count=c.execute("SELECT COUNT(*) n FROM reports WHERE status!='Resolved'").fetchone()["n"]
    resolved=c.execute("SELECT COUNT(*) n FROM reports WHERE status='Resolved'").fetchone()["n"]
    active_sos=c.execute("SELECT COUNT(*) n FROM sos WHERE status='ACTIVE'").fetchone()["n"]
    forwarded=c.execute("SELECT COUNT(*) n FROM reports WHERE status IN ('Forwarded','Security Action')").fetchone()["n"]
    cats=c.execute("SELECT category,COUNT(*) n FROM reports GROUP BY category ORDER BY n DESC").fetchall()
    if role=="student":
        student_user=session.get("login_user","")
        own=c.execute("SELECT * FROM reports WHERE student_user=? ORDER BY id DESC LIMIT 50",(student_user,)).fetchall()
        c.close()
        cases="".join(f"""<div class="case"><span class="pill">{r['public_id']}</span><h3>{r['title']}</h3><p class="muted">{r['category']} · {r['priority']} priority · <b>{r['status']}</b></p><p>{r['summary'] or r['description'][:180]}</p><div class="actions"><a class="btn primary small" href="/student/track?public_id={r['public_id']}">View Case History</a><a class="btn small" target="_blank" href="https://www.google.com/maps?q={r['latitude']},{r['longitude']}">Location</a></div></div>""" for r in own[:12]) or '<div class="card"><p class="muted">No submitted cases yet. Your submitted reports will automatically appear here.</p></div>'
        alerts_html="".join(f'<div class="alert {"critical" if a["severity"]=="Critical" else ""}"><b>{a["title"]}</b><p class="muted">{a["message"]}</p></div>' for a in alerts) or '<p class="muted">No active alerts.</p>'
        contacts_html="".join(f'<div class="card"><b>{x["name"]}</b><p class="muted">{x["description"]}</p><a class="btn small" href="tel:{x["phone"]}">Call {x["phone"]}</a></div>' for x in contacts+services)
        body=f"""<div class="pagehead"><div class="eyebrow">STUDENT PORTAL</div><h1>Your Safety Dashboard</h1><p class="muted">Report safely, share location when needed, track every case and access emergency support.</p></div>
<div class="grid g4"><div class="card stat"><span>OPEN CASES</span><strong>{open_count}</strong></div><div class="card stat"><span>RESOLVED</span><strong>{resolved}</strong></div><div class="card stat"><span>ACTIVE ALERTS</span><strong>{len(alerts)}</strong></div><div class="card stat"><span>LIVE LOCATION</span><strong>{"ON" if loc else "—"}</strong></div></div>
<div class="grid g3"><a class="card" href="/student/report"><h2>📝 Report Incident</h2><p class="muted">Anonymous report + evidence + Priority.</p></a><a class="card sosbox" href="/student/emergency"><h2>🚨 Emergency SOS</h2><p class="muted">Send GPS to Admin and activate response.</p></a><a class="card" href="/safety-map"><h2>🗺 Safety Map</h2><p class="muted">Campus safety points and support locations.</p></a></div>
<div class="grid g2"><div><div class="card"><h2>Campus Alerts</h2>{alerts_html}</div><div class="card"><h2>My Case Tracker</h2><div class="grid g2">{cases}</div></div></div><div><div class="card"><h2>Live Location</h2><div class="mapbox">{("<div class='mapdot' style='left:50%;top:48%'></div>" if loc else "")}</div><p class="muted">{(f"Last GPS: {loc['latitude']}, {loc['longitude']} · accuracy {loc['accuracy']}m" if loc else "Location not shared yet.")}</p><button class="btn primary" onclick="shareLocation()">Share / Refresh My Location</button><span id="locmsg" class="muted"></span></div><div class="card"><h2>Emergency Contacts & Services</h2>{contacts_html}</div></div></div>
<script>function shareLocation(){{if(!navigator.geolocation){{locmsg.textContent='Geolocation unavailable';return}}navigator.geolocation.getCurrentPosition(async p=>{{let r=await fetch('/student/location',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{latitude:p.coords.latitude,longitude:p.coords.longitude,accuracy:p.coords.accuracy}})}});let j=await r.json();locmsg.textContent=j.ok?' Location shared ✓':' '+j.error}},()=>locmsg.textContent=' Location permission denied')}}</script>"""
        return page("Student Safety Dashboard",body,role,"Dashboard")
    if role=="admin":
        sos_cards=""
        for s in sos:
            if s["status"] in ("ACTIVE","FORWARDED"):
                action=f'<form method="post" action="/admin/sos/{s["event_id"]}/forward"><button class="btn warn small">Forward to Security</button></form>' if s["status"]=="ACTIVE" else '<span class="pill">FORWARDED</span>'
                sos_cards+=f'<div class="case"><b>🚨 {s["event_id"]}</b><p class="muted">GPS {s["latitude"]}, {s["longitude"]} · {s["status"]}</p><a class="btn small" target="_blank" href="https://www.google.com/maps?q={s["latitude"]},{s["longitude"]}">Open Map</a> {action}</div>'
        report_cards=""
        for r in reports:
            if r["status"]!="Resolved":
                fwd=f'<form method="post" action="/admin/report/{r["public_id"]}/forward"><button class="btn warn small">Forward to Security</button></form>' if r["status"] in ("Submitted","Under Review") else '<span class="pill">IN SECURITY</span>'
                mc=db()
                mrows=mc.execute("SELECT * FROM messages WHERE public_id=? ORDER BY id", (r["public_id"],)).fetchall()
                mc.close()
                msg_html="".join(f'<div class="msg {m["sender"]}"><b>{m["sender"]}</b>: {m["message"]}<br><small>{m["created_at"]}</small></div>' for m in mrows) or '<p class="muted">No anonymous messages yet.</p>'
                analysis_action = "Review the report details and location, then forward to Security if immediate field response is required." if r["priority"] in ("High","Critical") else "Review the report and verify the details before forwarding or resolving the case."
                analysis_html=f'<div class="card" style="margin-top:12px"><b>🧠 Report Analysis</b><p><b>Priority:</b> {r["priority"]} &nbsp; <b>Tags:</b> {r["tags"] or "General"}</p><p><b>Summary:</b> {r["summary"] or r["description"][:240]}</p><p class="muted"><b>Suggested admin action:</b> {analysis_action}</p></div>'
                report_cards+=f'<div class="case"><span class="pill">{r["public_id"]}</span><h3>{r["title"]}</h3><p class="muted">{r["category"]} · <b>{r["priority"]}</b> · {r["status"]}</p><p>{r["description"][:280]}</p><p class="muted">GPS: {r["latitude"]}, {r["longitude"]}</p><a class="btn small" target="_blank" href="https://www.google.com/maps?q={r["latitude"]},{r["longitude"]}">Map</a> {fwd}<form method="post" action="/admin/report/{r["public_id"]}/status" style="display:inline"><input type="hidden" name="status" value="Under Review"><button class="btn small">Review</button></form>{analysis_html}<div class="card" style="margin-top:12px"><b>💬 Anonymous messages to Admin</b>{msg_html}</div></div>'
        bars="".join(f'<div style="display:grid;grid-template-columns:140px 1fr 30px;gap:8px;align-items:center;font-size:11px"><span>{x["category"]}</span><div style="height:9px;background:#e9eef5;border-radius:9px"><div style="width:{min(100,int(x["n"])*20)}%;height:9px;background:linear-gradient(90deg,#1769e0,#15b8c9);border-radius:9px"></div></div><b>{x["n"]}</b></div>' for x in cats) or '<p class="muted">No data yet.</p>'
        alarm_class = "" if active_sos==0 else "hidden"
        alarm=f"""<div id="alarm" class="card alarm {alarm_class}"><h2>🔊 ACTIVE SOS ALARM</h2><p>Continuous Admin alarm. It stops only after the active SOS is forwarded to Security.</p><button class="btn danger" onclick="enableAlarm()">Enable Alarm Sound</button></div>"""
        contacts_html="".join(f'<div class="case"><b>{x["name"]}</b><p class="muted">{x["kind"]} · {x["phone"]}</p><span class="pill">ACTIVE</span></div>' for x in contacts)
        body=f"""<div class="pagehead"><div class="eyebrow">ADMIN COMMAND CENTER</div><h1>Campus Safety Control Room</h1><p class="muted">Monitor incidents, severity, SOS events, live location, alerts, security forwarding, contacts and audit history.</p></div>
<div class="grid g4"><div class="card stat"><span>TOTAL REPORTS</span><strong>{total}</strong></div><div class="card stat"><span>CRITICAL</span><strong class="critical">{critical}</strong></div><div class="card stat"><span>OPEN</span><strong>{open_count}</strong></div><div class="card stat"><span>RESOLVED</span><strong class="ok">{resolved}</strong></div></div>
{alarm}
<div class="grid g2"><div class="card"><h2>📊 Incident Analytics</h2>{bars}</div><div class="card"><h2>📍 Latest Student Location</h2><div class="mapbox">{("<div class='mapdot' style='left:50%;top:50%'></div>" if loc else "")}</div><p class="muted">{(f"{loc['latitude']}, {loc['longitude']} · {loc['accuracy']}m" if loc else "No location shared.")}</p>{("<a class='btn small' target='_blank' href='https://www.google.com/maps?q="+str(loc["latitude"])+","+str(loc["longitude"])+"'>Open Google Maps</a>" if loc else "")}</div></div>
<div class="card"><h2>🚨 SOS Control Queue</h2>{sos_cards or '<p class="muted">No active SOS events.</p>'}</div>
<div class="card"><h2>🛡 Incident Queue + Incident Priority</h2>{report_cards or '<p class="muted">No unresolved reports.</p>'}</div>
<div class="grid g2"><div class="card"><h2>📢 Broadcast Safety Alert</h2><form class="form" method="post" action="/admin/alert"><input name="title" placeholder="Alert title" required><textarea name="message" placeholder="Message to campus/security" required></textarea><select name="severity"><option>Info</option><option>Warning</option><option>Critical</option></select><select name="audience"><option value="campus">Campus</option><option value="student">Students</option><option value="security">Security</option></select><button class="btn primary">Publish Alert</button></form></div><div class="card"><h2>☎ Contacts & Services</h2>{contacts_html}<hr><form class="form" method="post" action="/admin/contact"><input name="name" placeholder="Name" required><input name="kind" placeholder="Security / Medical / Helpline" required><input name="phone" placeholder="Phone" required><button class="btn">Add Contact</button></form></div></div>
<div class="card"><h2>🔐 Audit Activity</h2><div class="activity">{"".join(f'<p><b>{l["action"]}</b> · {l["ref"] or ""}<br><span class="muted">{l["details"]} · {l["created_at"]}</span></p>' for l in logs) or '<p class="muted">No activity yet.</p>'}</div></div>
<script>let audio=null,timer=null;function enableAlarm(){{if(!audio)audio=new AudioContext();if(timer)return;let o=audio.createOscillator(),g=audio.createGain();o.frequency.value=880;g.gain.value=.08;o.connect(g);g.connect(audio.destination);o.start();timer=setInterval(()=>o.frequency.value=o.frequency.value==880?660:880,450)}}async function poll(){{let r=await fetch('/admin/sos/active');let j=await r.json();document.getElementById('alarm').classList.toggle('hidden',!j.active);if(!j.active&&timer){{clearInterval(timer);timer=null;if(audio){{audio.close();audio=null}}}}}}setInterval(poll,2000)</script>"""
        return page("Admin Command Center",body,role,"Command Center")
    forwarded_cases=[r for r in reports if r["status"] in ("Forwarded","Security Action")]
    sos_forwarded=[s for s in sos if s["status"]=="FORWARDED"]
    cases="".join(f"""<div class="case"><span class="pill">{r['public_id']}</span><h3>{r['title']}</h3><p class="muted">{r['category']} · {r['priority']} · {r['status']}</p><p>{r['description'][:260]}</p><p class="muted">Location: {r['latitude']}, {r['longitude']}</p><form class="form" method="post" action="/security/report/{r['public_id']}/resolve"><input name="note" placeholder="Action taken / resolution note" required><button class="btn success">Take Action → Problem Solved</button></form></div>""" for r in forwarded_cases)
    sosq="".join(f"""<div class="case"><b>🚨 {s['event_id']}</b><p class="muted">GPS {s['latitude']}, {s['longitude']} · Forwarded by Admin</p><a class="btn small" target="_blank" href="https://www.google.com/maps?q={s['latitude']},{s['longitude']}">Open Map</a><form class="form" method="post" action="/security/sos/{s['event_id']}/resolve"><input name="note" placeholder="Security action taken" required><button class="btn success">Take Action → Problem Solved</button></form></div>""" for s in sos_forwarded)
    body=f"""<div class="pagehead"><div class="eyebrow">SECURITY RESPONSE CENTER</div><h1>Security Operations Dashboard</h1><p class="muted">Only Admin-forwarded cases enter this queue. Take action, record evidence/notes and close the incident.</p></div>
<div class="grid g4"><div class="card stat"><span>FORWARDED CASES</span><strong>{len(forwarded_cases)}</strong></div><div class="card stat"><span>FORWARDED SOS</span><strong>{len(sos_forwarded)}</strong></div><div class="card stat"><span>OPEN TOTAL</span><strong>{open_count}</strong></div><div class="card stat"><span>LIVE LOCATION</span><strong>{"YES" if loc else "—"}</strong></div></div>
<div class="grid g2"><div class="card"><h2>🚨 SOS Response Queue</h2>{sosq or '<p class="muted">No forwarded SOS.</p>'}</div><div class="card"><h2>📍 Latest Live Location</h2><div class="mapbox">{("<div class='mapdot' style='left:50%;top:50%'></div>" if loc else "")}</div><p class="muted">{(f"{loc['latitude']}, {loc['longitude']} · accuracy {loc['accuracy']}m" if loc else "No location shared.")}</p></div></div>
<div class="card"><h2>🛡 Forwarded Incident Reports</h2><div class="grid g2">{cases or '<p class="muted">No forwarded reports awaiting action.</p>'}</div></div>
<div class="card"><h2>📍 Campus Safety Points</h2><div class="grid g3">{"".join(f'<div class="case"><b>{p["name"]}</b><p class="muted">{p["kind"]} · {p["location"]}</p><p>{p["description"]}</p></div>' for p in points)}</div></div>"""
    return page("Security Operations",body,role,"Security Dashboard")

@app.route("/report",methods=["GET","POST"])
@auth("student")
def report_alias():
    return report()

@app.route("/student/report",methods=["GET","POST"])
@auth("student")
def report():
    if request.method=="POST":
        cat=request.form.get("category",""); title=request.form.get("title","").strip(); desc=request.form.get("description","").strip()
        if not title or not desc or cat not in CATEGORIES: flash("Complete all required fields."); return redirect(url_for("report"))
        try: lat=float(request.form.get("latitude")) if request.form.get("latitude") else None; lng=float(request.form.get("longitude")) if request.form.get("longitude") else None; acc=float(request.form.get("accuracy")) if request.form.get("accuracy") else None
        except ValueError: lat=lng=acc=None
        priority,summary,tags=classify_report(cat,title,desc,request.form.get("severity","Medium"))
        rid="CS-"+secrets.token_hex(4).upper(); token=secrets.token_urlsafe(18); ev=request.files.get("evidence"); en=""; ep=""
        if ev and ev.filename:
            safe=secrets.token_hex(5)+"_"+Path(ev.filename).name; ev.save(UPLOADS/safe); en=ev.filename; ep=safe
        c=db(); c.execute("""INSERT INTO reports(public_id,tracking_token,student_user,category,title,description,location,incident_date,severity,priority,summary,tags,evidence_name,evidence_path,status,latitude,longitude,accuracy,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(rid,token,session.get("login_user","student"),cat,title,desc,request.form.get("location",""),request.form.get("incident_date",""),request.form.get("severity","Medium"),priority,summary,tags,en,ep,"Submitted",lat,lng,acc,now(),now())); c.execute("INSERT INTO messages(public_id,sender,message,created_at) VALUES(?,?,?,?)",(rid,"system","Report submitted and added to your case history.",now())); c.commit(); c.close(); audit("Report submitted",rid,"Anonymous report with severity classification: "+priority)
        student_reports=session.get("student_reports",[])
        if rid not in student_reports: student_reports.append(rid)
        session["student_reports"]=student_reports[-50:]
        body=f"""<div class="pagehead"><div class="eyebrow">REPORT RECEIVED</div><h1>Your report is now visible in your private tracker.</h1><p class="muted">Save the Tracking ID and Private Token. You can use them to follow the case and send anonymous messages to the Admin.</p></div><div class="grid g2"><div class="card"><span class="pill">TRACKING ID</span><h2>{rid}</h2><p><b>{title}</b></p><p class="muted">{cat} · {request.form.get("severity","Medium")} · Priority {priority}</p><p>{desc}</p><p class="muted">Location: {request.form.get("location","") or "Not specified"}</p><p class="muted">GPS: {lat}, {lng}</p></div><div class="card"><span class="pill">PRIVATE TOKEN</span><h2 style="word-break:break-all">{token}</h2><p class="muted">Do not share this token. It is the private key for this anonymous case.</p><a class="btn primary" href="/student/track?public_id={rid}">Track My Report</a></div></div><div class="card"><h2>💬 Anonymous message to Admin</h2><p class="muted">Ask for an update, add useful information, or explain anything you could not include in the report.</p><form class="form" method="post" action="/student/track/{rid}/message"><input type="hidden" name="token" value="{token}"><textarea name="message" placeholder="Write a private message to Admin..." required></textarea><button class="btn">Send Message to Admin</button></form></div>"""
        return page("Report Submitted",body,"student","Report Incident")
    body=f"""<div class="pagehead"><div class="eyebrow">ANONYMOUS REPORTING</div><h1>Report an Incident</h1><p class="muted">Your identity is not shown in the incident workflow. Include accurate details and location only when useful for response.</p></div><div class="card"><form class="form" method="post" enctype="multipart/form-data"><div class="grid g2"><label>Category<select name="category">{"".join(f"<option>{x}</option>" for x in CATEGORIES)}</select></label><label>Severity<select name="severity">{"".join(f"<option>{x}</option>" for x in SEVERITIES)}</select></label></div><label>Incident title<input name="title" placeholder="Short description" required></label><label>What happened?<textarea name="description" required></textarea></label><div class="grid g2"><label>Location<input name="location" placeholder="Block / hostel / area"></label><label>Date / time<input type="datetime-local" name="incident_date"></label></div><label>Evidence (optional)<input type="file" name="evidence"></label><input type="hidden" name="latitude" id="lat"><input type="hidden" name="longitude" id="lng"><input type="hidden" name="accuracy" id="acc"><button class="btn primary">Submit Secure Report</button></form></div><script>navigator.geolocation?.getCurrentPosition(p=>{{lat.value=p.coords.latitude;lng.value=p.coords.longitude;acc.value=p.coords.accuracy}})</script>"""
    return page("Report Incident",body,"student","Report Incident")

@app.route("/track",methods=["GET","POST"])
@auth("student")
def track_alias():
    return track()

@app.route("/student/track",methods=["GET","POST"])
@auth("student")
def track():
    if request.method=="POST": return redirect(url_for("track",public_id=request.form.get("public_id","")))
    rid=request.args.get("public_id","").strip(); c=db(); owned_ids={x["public_id"] for x in session.get("student_reports",[])}; r=c.execute("SELECT * FROM reports WHERE public_id=? AND student_user=?",(rid,session.get("login_user",""))).fetchone() if rid else None; msgs=c.execute("SELECT * FROM messages WHERE public_id=? ORDER BY id", (rid,)).fetchall() if r else []; c.close()
    if not r: return redirect(url_for("portal",role="student"))
    else:
        submitted_cls="ok" if r["status"] in ("Submitted","Under Review","Forwarded","Security Action","Resolved") else ""
        review_cls="ok" if r["status"] in ("Under Review","Forwarded","Security Action","Resolved") else ""
        security_cls="ok" if r["status"] in ("Forwarded","Security Action","Resolved") else ""
        resolved_cls="ok" if r["status"]=="Resolved" else ""
        token=r["tracking_token"]
        body=f"""<div class="pagehead"><div class="eyebrow">CASE HISTORY · {r['public_id']}</div><h1>{r['title']}</h1><p class="muted">{r['category']} · Priority {r['priority']}</p></div><div class="timeline"><div class="card {submitted_cls}">1 · Submitted</div><div class="card {review_cls}">2 · Review</div><div class="card {security_cls}">3 · Security</div><div class="card {resolved_cls}">4 · Resolved</div></div><div class="grid g2"><div class="card"><h2>Status: {r['status']}</h2><p>{r['summary']}</p><p class="muted">Location: {r['location'] or "Not specified"} · GPS {r['latitude']}, {r['longitude']}</p><p class="muted">Admin note: {r['admin_note'] or "No update yet."}</p><p class="muted">Security note: {r['security_note'] or "No security action yet."}</p></div><div class="card"><h2>Anonymous Conversation</h2><div class="chat">{"".join(f'<div class="msg {m["sender"]}"><b>{m["sender"]}</b><br>{m["message"]}<br><small>{m["created_at"]}</small></div>' for m in msgs) or '<p class="muted">No messages.</p>'}</div><form class="form" method="post" action="/student/track/{r["public_id"]}/message"><input type="hidden" name="token" value="{token}"><input name="message" placeholder="Send a private message"><button class="btn">Send</button></form></div></div>"""
    return page("Case Tracker",body,"student","Track Case")

@app.route("/student/track/<rid>/message",methods=["POST"])
@auth("student")
def student_message(rid):
    c=db(); r=c.execute("SELECT * FROM reports WHERE public_id=? AND student_user=?",(rid,session.get("login_user",""))).fetchone()
    if r and request.form.get("message","").strip(): c.execute("INSERT INTO messages(public_id,sender,message,created_at) VALUES(?,?,?,?)",(rid,"student",request.form["message"].strip(),now())); c.commit()
    c.close(); return redirect(url_for("track",public_id=rid))

@app.route("/emergency")
@auth("student")
def emergency_alias():
    return emergency()

@app.route("/student/emergency")
@auth("student")
def emergency():
    c=db(); contacts=c.execute("SELECT * FROM contacts WHERE active=1").fetchall(); c.close()
    body=f"""<div class="pagehead"><div class="eyebrow">EMERGENCY RESPONSE</div><h1>Emergency SOS</h1><p class="muted">Press once to capture GPS and create an ACTIVE emergency event. Admin receives it immediately. Keep this page open until help is confirmed.</p></div><div class="card sosbox" style="text-align:center"><button class="sosbtn" onclick="sos()">SOS</button><p id="smsg" class="muted"></p></div><div class="grid g3">{"".join(f'<div class="card"><h3>{x["name"]}</h3><p class="muted">{x["description"]}</p><a class="btn small" href="tel:{x["phone"]}">Call {x["phone"]}</a></div>' for x in contacts)}</div><script>async function sos(){{if(!navigator.geolocation){{smsg.textContent="GPS unavailable";return}}navigator.geolocation.getCurrentPosition(async p=>{{let r=await fetch('/student/sos',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{latitude:p.coords.latitude,longitude:p.coords.longitude}})}});let j=await r.json();smsg.textContent=j.message||j.error}},()=>smsg.textContent="Location permission is required")}}</script>"""
    return page("Emergency SOS",body,"student","Emergency SOS")

@app.route("/student/sos",methods=["POST"])
@auth("student")
def create_sos():
    d=request.get_json(silent=True) or {}
    try: lat=float(d["latitude"]); lng=float(d["longitude"])
    except: return jsonify(ok=False,error="Valid GPS coordinates are required"),400
    eid="SOS-"+secrets.token_hex(4).upper(); c=db(); c.execute("INSERT INTO sos(event_id,latitude,longitude,created_at) VALUES(?,?,?,?)",(eid,lat,lng,now())); c.execute("INSERT INTO locations(student_label,latitude,longitude,accuracy,created_at) VALUES(?,?,?,?,?)",("Anonymous Student",lat,lng,0,now())); c.commit(); c.close(); audit("SOS triggered",eid,f"GPS {lat},{lng}"); return jsonify(ok=True,event_id=eid,message=f"SOS {eid} sent to Admin with GPS location. Keep this page open and contact campus emergency services if you are in immediate danger.")

@app.route("/student/location",methods=["POST"])
@auth("student")
def student_location():
    d=request.get_json(silent=True) or {}
    try: lat=float(d["latitude"]); lng=float(d["longitude"]); acc=float(d.get("accuracy",0))
    except: return jsonify(ok=False,error="Invalid coordinates"),400
    c=db(); c.execute("INSERT INTO locations(student_label,latitude,longitude,accuracy,created_at) VALUES(?,?,?,?,?)",("Anonymous Student",lat,lng,acc,now())); c.commit(); c.close(); audit("Live location updated","","Student location refreshed"); return jsonify(ok=True)

@app.route("/admin/sos/active")
@auth("admin")
def active_sos():
    c=db(); n=c.execute("SELECT COUNT(*) n FROM sos WHERE status='ACTIVE'").fetchone()["n"]; c.close(); return jsonify(active=n>0,count=n)

@app.route("/admin/sos/<eid>/forward",methods=["POST"])
@auth("admin")
def forward_sos(eid):
    c=db(); r=c.execute("SELECT * FROM sos WHERE event_id=? AND status='ACTIVE'",(eid,)).fetchone()
    if not r: c.close(); return "SOS not active",404
    c.execute("UPDATE sos SET status='FORWARDED',forwarded_at=? WHERE event_id=?",(now(),eid))
    c.execute("INSERT INTO alerts(title,message,severity,audience,created_at,location_snapshot) VALUES(?,?,?,?,?,?)",(f"Emergency SOS {eid}","Admin forwarded SOS to Security for immediate action.","Critical","security",now(),json.dumps(dict(r))))
    c.commit(); c.close(); audit("SOS forwarded to Security",eid,"Same GPS location forwarded"); return redirect(url_for("portal",role="admin"))

@app.route("/admin/report/<rid>/forward",methods=["POST"])
@auth("admin")
def forward_report(rid):
    c=db(); r=c.execute("SELECT * FROM reports WHERE public_id=?",(rid,)).fetchone()
    if not r: c.close(); return "Not found",404
    c.execute("UPDATE reports SET status='Forwarded',forwarded_at=?,updated_at=? WHERE public_id=? AND status!='Resolved'",(now(),now(),rid)); c.execute("INSERT INTO messages(public_id,sender,message,created_at) VALUES(?,?,?,?)",(rid,"admin","Admin forwarded this case to Security with the recorded location.",now()))
    c.execute("INSERT INTO alerts(title,message,severity,audience,created_at,report_public_id,location_snapshot) VALUES(?,?,?,?,?,?,?)",(f"Security Action Required • {rid}",r["title"],"Critical" if r["priority"]=="Critical" else "Warning","security",now(),rid,json.dumps({"latitude":r["latitude"],"longitude":r["longitude"]})))
    c.commit(); c.close(); audit("Report forwarded to Security",rid,"Location snapshot included"); return redirect(url_for("portal",role="admin"))

@app.route("/admin/report/<rid>/status",methods=["POST"])
@auth("admin")
def admin_status(rid):
    status=request.form.get("status","Under Review")
    if status not in STATUSES: return "Bad status",400
    c=db(); note=request.form.get("note","").strip()
    c.execute("UPDATE reports SET status=?,admin_note=?,updated_at=? WHERE public_id=?",(status,note,now(),rid)); c.execute("INSERT INTO messages(public_id,sender,message,created_at) VALUES(?,?,?,?)",(rid,"admin",f"Admin updated case status to {status}."+(" Note: "+note if note else ""),now())); c.commit(); c.close(); audit("Admin status update",rid,status); return redirect(url_for("portal",role="admin"))

@app.route("/security/sos/<eid>/resolve",methods=["POST"])
@auth("security")
def resolve_sos(eid):
    c=db(); c.execute("UPDATE sos SET status='RESOLVED',security_note=?,resolved_at=? WHERE event_id=? AND status='FORWARDED'",(request.form.get("note",""),now(),eid)); c.commit(); c.close(); audit("SOS resolved",eid,request.form.get("note","")); return redirect(url_for("portal",role="security"))

@app.route("/security/report/<rid>/resolve",methods=["POST"])
@auth("security")
def resolve_report(rid):
    c=db(); note=request.form.get("note","").strip()
    c.execute("UPDATE reports SET status='Resolved',security_note=?,resolved_at=?,updated_at=? WHERE public_id=? AND status IN ('Forwarded','Security Action')",(note,now(),now(),rid)); c.execute("INSERT INTO messages(public_id,sender,message,created_at) VALUES(?,?,?,?)",(rid,"security",f"Security marked the case Resolved."+(" Note: "+note if note else ""),now())); c.commit(); c.close(); audit("Report resolved",rid,request.form.get("note","")); return redirect(url_for("portal",role="security"))

@app.route("/admin/alert",methods=["POST"])
@auth("admin")
def add_alert():
    c=db(); c.execute("INSERT INTO alerts(title,message,severity,audience,created_at) VALUES(?,?,?,?,?)",(request.form["title"],request.form["message"],request.form.get("severity","Info"),request.form.get("audience","campus"),now())); c.commit(); c.close(); audit("Alert broadcast","","Published "+request.form.get("audience","campus")); return redirect(url_for("portal",role="admin"))

@app.route("/admin/contact",methods=["POST"])
@auth("admin")
def add_contact():
    c=db(); c.execute("INSERT INTO contacts(name,kind,phone,description) VALUES(?,?,?,?)",(request.form["name"],request.form["kind"],request.form["phone"],request.form.get("description",""))); c.commit(); c.close(); return redirect(url_for("portal",role="admin"))

@app.route("/map")
def safety_map_alias():
    return safety_map()

@app.route("/safety-map")
def safety_map():
    c=db(); points=c.execute("SELECT * FROM safety_points").fetchall(); c.close()
    body=f"""<div class="pagehead"><div class="eyebrow">KALASALINGAM UNIVERSITY</div><h1>Campus Safety Map</h1><p class="muted">Safety, medical, support and emergency points.</p></div><div class="grid g2"><div class="mapbox"><a class="btn primary" style="position:absolute;z-index:3;left:18px;top:18px" target="_blank" href="https://www.google.com/maps/search/?api=1&query=Kalasalingam+Academy+of+Research+and+Education">Open Google Maps</a>{"".join(f'<div class="mapdot" style="left:{20+i*15}%;top:{25+(i%3)*20}%"></div>' for i,p in enumerate(points))}</div><div class="grid">{"".join(f'<div class="card"><b>{p["name"]}</b><p class="muted">{p["kind"]} · {p["location"]}</p><p>{p["description"]}</p></div>' for p in points)}</div></div>"""
    return page("Safety Map",body)

@app.route("/resources")
def resources():
    body="""<div class="pagehead"><div class="eyebrow">SUPPORT</div><h1>Safety Resources</h1></div><div class="grid g3"><div class="card"><h2>Emergency</h2><p class="muted">Use SOS for immediate campus response. National emergency number: 112.</p></div><div class="card"><h2>Digital Safety</h2><p class="muted">Preserve screenshots, messages and account details when reporting cyber incidents.</p></div><div class="card"><h2>Safe Movement</h2><p class="muted">Use known campus safety points and contact Security when an area feels unsafe.</p></div></div>"""
    return page("Safety Resources",body)

@app.route("/privacy")
def privacy():
    return page("Privacy",'<div class="pagehead"><div class="eyebrow">PRIVACY</div><h1>Privacy & Data Handling</h1></div><div class="card"><h2>Anonymous reporting</h2><p class="muted">The case workflow uses a private tracking token instead of displaying a student identity. GPS is stored only when the student shares it or uses SOS. Evidence is stored under generated filenames. Admin and Security actions are recorded in an audit trail for accountability.</p></div>')

@app.route("/health")
def health(): return jsonify(ok=True,service="CAMPUS SHAKTHI",version="2.0")

@app.route("/uploads/<name>")
@auth("admin")
def upload(name): return send_from_directory(UPLOADS,name,as_attachment=True)

if __name__=="__main__": app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)))


