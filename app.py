import os,json,pickle,ssl,socket,datetime,hashlib,sqlite3,re
import pandas as pd
from functools import wraps
from urllib.parse import urlparse
from flask import Flask,request,jsonify,render_template,redirect,url_for,session

app=Flask(__name__); app.secret_key="phishguard-secret-2026"
BASE=os.path.dirname(os.path.abspath(__file__))
import sys; sys.path.insert(0,BASE)
from feature_extraction import extract_features
from blacklist import is_blacklisted,add_to_blacklist,get_blacklist,get_blacklist_count,remove_from_blacklist
from whitelist import is_whitelisted

# ─── Database ──────────────────────────────────────────────────────────────────
DB=os.path.join(BASE,"phishguard.db")
def get_conn():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def _safe(row):
    if row is None: return {}
    d={}
    for k in row.keys():
        v=row[k]
        if isinstance(v,bytes):
            try: v=v.decode("utf-8")
            except: v=v.hex()
        if not isinstance(v,(str,int,float,bool,type(None))): v=str(v)
        d[k]=v
    return d

def init_db():
    conn=get_conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS scan_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT DEFAULT '',
        url TEXT NOT NULL,result TEXT NOT NULL,confidence REAL DEFAULT 0.0,
        detection_layer TEXT DEFAULT 'ml',scanned_at TEXT NOT NULL)""")
    try: conn.execute("ALTER TABLE scan_history ADD COLUMN username TEXT DEFAULT ''")
    except: pass
    conn.execute("""CREATE TABLE IF NOT EXISTS threat_stats(
        id INTEGER PRIMARY KEY AUTOINCREMENT,date TEXT NOT NULL UNIQUE,
        phishing_count INTEGER DEFAULT 0,safe_count INTEGER DEFAULT 0)""")
    conn.commit(); conn.close(); print("✅ Database ready")

init_db()

def log_user_scan(username,url,result,conf,layer):
    conn=get_conn()
    now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    today=datetime.datetime.now().strftime("%Y-%m-%d")
    conn.execute("INSERT INTO scan_history(username,url,result,confidence,detection_layer,scanned_at)VALUES(?,?,?,?,?,?)",
                 (username,url,result,float(conf),layer,now))
    conn.execute("INSERT INTO threat_stats(date,phishing_count,safe_count)VALUES(?,0,0)ON CONFLICT(date)DO NOTHING",(today,))
    if result=="phishing": conn.execute("UPDATE threat_stats SET phishing_count=phishing_count+1 WHERE date=?",(today,))
    else: conn.execute("UPDATE threat_stats SET safe_count=safe_count+1 WHERE date=?",(today,))
    conn.commit(); conn.close()

def get_user_scans(username,limit=200):
    conn=get_conn()
    rows=conn.execute("SELECT * FROM scan_history WHERE username=? ORDER BY scanned_at DESC LIMIT?",(username,limit)).fetchall()
    conn.close(); return [_safe(r) for r in rows]

def clear_user_history(username):
    conn=get_conn(); conn.execute("DELETE FROM scan_history WHERE username=?",(username,)); conn.commit(); conn.close()

def get_today_stats():
    conn=get_conn(); today=datetime.datetime.now().strftime("%Y-%m-%d")
    row=conn.execute("SELECT * FROM threat_stats WHERE date=?",(today,)).fetchone()
    conn.close(); return _safe(row) if row else {"date":today,"phishing_count":0,"safe_count":0}

def get_user_stats(username):
    conn=get_conn()
    rows=conn.execute("SELECT result FROM scan_history WHERE username=?",(username,)).fetchall()
    conn.close(); total=len(rows); ph=sum(1 for r in rows if r[0]=="phishing")
    return {"total":total,"phishing":ph,"safe":total-ph}

# ─── Users ─────────────────────────────────────────────────────────────────────
USERS_FILE=os.path.join(BASE,"users.json")
def load_users():
    return json.load(open(USERS_FILE)) if os.path.exists(USERS_FILE) else {}
def save_users(u): json.dump(u,open(USERS_FILE,"w"),indent=2)
def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()
def get_user(un): return load_users().get(un.lower())

# ─── Models ──────────────────────────────────────────────────────────────────
MODELS,SCALER,FEAT_NAMES,MODEL_RESULTS,FEAT_IMP={},None,[],{},{}
SCALED={"mlp","logistic_regression","knn"}
MNAMES={"xgboost":"XGBoost","gradient_boosting":"Gradient Boosting",
        "random_forest":"Random Forest","decision_tree":"Decision Tree",
        "mlp":"MLP Classifier","logistic_regression":"Logistic Regression",
        "knn":"K-Nearest Neighbors","naive_bayes":"Naive Bayes"}
LOADED=False

def load_models():
    global MODELS,SCALER,FEAT_NAMES,MODEL_RESULTS,FEAT_IMP,LOADED
    d=os.path.join(BASE,"models")
    if not os.path.exists(d): return
    try:
        SCALER=pickle.load(open(f"{d}/scaler.pkl","rb"))
        FEAT_NAMES=pickle.load(open(f"{d}/feature_names.pkl","rb"))
        MODEL_RESULTS=json.load(open(f"{d}/results.json"))
        FEAT_IMP=json.load(open(f"{d}/feature_importances.json"))
        for fn in os.listdir(d):
            if fn.endswith(".pkl") and fn not in("scaler.pkl","feature_names.pkl"):
                k=fn.replace(".pkl","")
                if k in MNAMES: MODELS[k]=pickle.load(open(f"{d}/{fn}","rb"))
        LOADED=bool(MODELS); print(f"✅ {len(MODELS)} models loaded")
    except Exception as e: print(f"Model error:{e}")

load_models()

# ─── Domain Age ──────────────────────────────────────────────────────────────
def get_domain_age(url):
    result={"age_days":None,"created":None,"registrar":None,"checked":False,"note":""}
    try:
        import whois
        parsed=urlparse(url if url.startswith("http") else "http://"+url)
        domain=re.sub(r'^www\.','',(parsed.hostname or "").lower())
        w=whois.whois(domain)
        created=w.creation_date
        if isinstance(created,list): created=created[0]
        if created:
            if isinstance(created,str):
                created=datetime.datetime.strptime(created[:10],"%Y-%m-%d")
            if created.tzinfo is None:
                created=created.replace(tzinfo=datetime.timezone.utc)
            else:
                created=created.astimezone(datetime.timezone.utc)
            now=datetime.datetime.now(datetime.timezone.utc)
            age=(now-created).days
            if age<0: age=0
            result.update({"age_days":age,"created":created.strftime("%d %b %Y"),
                           "registrar":str(w.registrar or "Unknown")[:60],"checked":True})
        else: result["note"]="Creation date not found"
    except ImportError: result["note"]="pip install python-whois"
    except Exception as e: result["note"]=str(e)[:60]
    return result

# ─── SSL ─────────────────────────────────────────────────────────────────────
def check_ssl(url):
    try:
        h=urlparse(url if url.startswith("http") else "https://"+url).hostname
        if not h: return {"valid":False,"error":"No hostname"}
        ctx=ssl.create_default_context()
        with socket.create_connection((h,443),timeout=5) as s:
            with ctx.wrap_socket(s,server_hostname=h) as ss:
                c=ss.getpeercert(); exp=c.get("notAfter","")
                ed=datetime.datetime.strptime(exp,"%b %d %H:%M:%S %Y %Z") if exp else None
                dl=(ed-datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days if ed else None
                iss=dict(x[0] for x in c.get("issuer",[]))
                return {"valid":True,"issuer":iss.get("organizationName","?"),
                        "expiry":ed.strftime("%d %b %Y") if ed else "?","days":dl,"version":ss.version()}
    except Exception as e: return {"valid":False,"error":str(e)[:60]}

# ─── Constants ───────────────────────────────────────────────────────────────
RISKY_TLDS={
    ".tk",".ml",".ga",".cf",".gq",
    ".top",".click",".download",".zip",
    ".review",".loan",".bid",".win",
    ".fun",".buzz",".website",".space",
    ".online",".site",".xyz",
}

SUSP_KW=["login","signin","verify","secure","account","banking","password",
         "paypal","paytm","update","confirm","suspended","alert","urgent",
         "billing","recovery"]

ABUSED_HOSTING={
    "web.app","firebaseapp.com","pages.dev","netlify.app",
    "vercel.app","glitch.me","github.io","surge.sh",
    "000webhostapp.com","weebly.com","wixsite.com",
    "weeblysite.com","mystrikingly.com","carrd.co","webflow.io",
}

PHISHING_KW_HOST=[
    "login","signin","sign-in","verify","verification",
    "secure","security","account","banking","bank",
    "payment","pay","billing","invoice","update",
    "confirm","validate","suspend","suspended","locked",
    "unlock","password","passwd","credential","recovery",
    "reactivate","alert","urgent",
    "paypal","paytm","apple","microsoft","facebook",
    "instagram","netflix","amazon","google","ebay",
    "sbi","hdfc","icici","axis","kotak",
]

BRAND_NAMES=[
    "paypal","paytm","apple","microsoft","facebook",
    "instagram","netflix","amazon","google","ebay",
    "twitter","whatsapp","linkedin","sbi","hdfc","icici",
]

RISKY_TLDS_SET={
    ".tk",".ml",".ga",".cf",".gq",
    ".top",".click",".download",".zip",
    ".review",".loan",".bid",".win",
    ".fun",".buzz",".website",".space",
    ".online",".site",".xyz",
}

SHORT_DOMAINS={
    "bit.ly","tinyurl.com","t.co","ow.ly","goo.gl","is.gd",
    "shorturl.at","rebrand.ly","cutt.ly","tiny.cc","buff.ly",
    "snip.ly","adf.ly","dlvr.it","lnkd.in","bl.ink",
}

# ─── Root domain helper ───────────────────────────────────────────────────────
def _get_root_domain(hostname):
    parts=hostname.split(".")
    if len(parts)<=2: return hostname
    cc_slds={"co.in","co.uk","com.au","co.nz","co.jp","co.za",
             "ac.in","edu.in","gov.in","net.in","org.in",
             "co.kr","co.id","com.br","com.mx","com.ar"}
    last_two=".".join(parts[-2:])
    if last_two in cc_slds and len(parts)>=3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

# ─── Phishing Reasons ────────────────────────────────────────────────────────
def generate_reasons(url,feats,conf,layer,ssl_r,domain_age):
    reasons=[]; safe_pts=[]
    parsed=urlparse(url if url.startswith("http") else "http://"+url)
    hostname=(parsed.hostname or "").lower()
    tld="."+hostname.split(".")[-1] if "." in hostname else ""

    if layer=="blacklist":
        reasons.append({"icon":"🚫","level":"critical","text":"Matches a known phishing URL in the threat database"})
    if feats.get("has_ip"):
        reasons.append({"icon":"🔢","level":"high","text":"IP address used instead of domain — phishers use raw IPs to avoid domain blacklists"})
    if not feats.get("has_https"):
        reasons.append({"icon":"🔓","level":"high","text":"No HTTPS — data sent in plain text, easily intercepted by attackers"})

    if feats.get("has_suspicious_keyword"):
        kws=[k for k in SUSP_KW if k in hostname.lower()]
        if kws:
            reasons.append({"icon":"⚠️","level":"high","text":f"Suspicious keyword(s) in domain name: {', '.join(kws[:3])} — brand names embedded in hostname are a strong phishing signal"})

    if tld in RISKY_TLDS:
        reasons.append({"icon":"🌐","level":"high","text":f"Risky TLD '{tld}' — free/abused domain extension frequently used for phishing"})
    if feats.get("num_at",0)>0:
        reasons.append({"icon":"@","level":"high","text":"@ symbol in URL — classic trick to disguise real destination after the @ sign"})
    if feats.get("num_subdomains",0)>=4:
        reasons.append({"icon":"🔗","level":"medium","text":f"{feats['num_subdomains']} subdomain levels — mimics legitimate sites (e.g. paypal.secure.evil.com)"})
    if feats.get("url_length",0)>150:
        reasons.append({"icon":"📏","level":"medium","text":f"URL is {feats['url_length']} chars — abnormally long URLs hide real destination"})
    if feats.get("has_port"):
        reasons.append({"icon":"🔌","level":"medium","text":"Non-standard port detected — legitimate sites rarely expose custom ports"})
    if feats.get("num_hyphens",0)>4:
        reasons.append({"icon":"➖","level":"low","text":f"{feats['num_hyphens']} hyphens — fake domains use hyphens to imitate real brands"})

    # ── Abused free hosting check ─────────────────────────────────────────────
    _h_parts=hostname.split(".")
    _root2=".".join(_h_parts[-2:])
    _root3=".".join(_h_parts[-3:])
    _matched_platform=None
    if _root2 in ABUSED_HOSTING and hostname!=_root2:
        _matched_platform=_root2
    elif _root3 in ABUSED_HOSTING and hostname!=_root3:
        _matched_platform=_root3
    if _matched_platform:
        reasons.append({"icon":"☁️","level":"high",
            "text":f"Hosted on free platform '{_matched_platform}' — commonly abused by phishers "
                   f"because it provides free SSL and trusted-looking domains"})

    # ── Domain age ────────────────────────────────────────────────────────────
    age=domain_age.get("age_days")
    if domain_age.get("checked") and age is not None:
        if age<30:
            reasons.append({"icon":"📅","level":"high","text":f"Domain only {age} days old — newly registered domains are a major phishing red flag"})
        elif age<180:
            reasons.append({"icon":"📅","level":"medium","text":f"Domain is {age} days old — relatively new domains carry higher phishing risk"})
        else:
            if len(reasons)==0:
                safe_pts.append({"icon":"✅","text":f"Domain age: {age} days (registered {domain_age['created']}) — established domain"})

    # ── SSL ───────────────────────────────────────────────────────────────────
    if ssl_r.get("valid"):
        days=ssl_r.get("days",0)
        if days and days<30:
            reasons.append({"icon":"🔐","level":"medium","text":f"SSL expires in {days} days — phishing sites use short-lived certificates"})
        else:
            if len(reasons)==0:
                safe_pts.append({"icon":"✅","text":f"Valid SSL from {ssl_r.get('issuer','?')} — expires {ssl_r.get('expiry','?')}"})
    else:
        err=ssl_r.get("error","unknown")
        _skip_errs=["timeout","timed out","connect","refused","network","unreachable","wrong version","wrong_version"]
        if any(x in err.lower() for x in _skip_errs):
            safe_pts.append({"icon":"ℹ️","text":"SSL check inconclusive — no certificate verdict available"})
        else:
            reasons.append({"icon":"🔓","level":"high","text":f"SSL failed: {err} — cannot verify site authenticity"})

    # ── HTTPS safe point — only if zero risks ─────────────────────────────────
    if (feats.get("has_https") and not feats.get("has_ip")
            and not feats.get("has_suspicious_keyword")
            and len(reasons)==0):
        safe_pts.append({"icon":"✅","text":"Uses HTTPS with no suspicious URL patterns"})

    # ── ML confidence reason ──────────────────────────────────────────────────
    if layer in ("ml","rule-based") and conf>=70:
        if conf>=90:
            reasons.append({"icon":"🤖","level":"high",
                "text":f"ML ensemble flagged with {conf}% confidence — "
                       f"structural patterns match known phishing campaigns even without obvious keywords"})
        else:
            reasons.append({"icon":"🤖","level":"info",
                "text":f"ML model flagged with {conf}% confidence after analyzing 31 URL structural and lexical features"})

    crit=sum(1 for r in reasons if r.get("level")=="critical")
    high=sum(1 for r in reasons if r.get("level")=="high")
    med=sum(1 for r in reasons if r.get("level")=="medium")
    if crit>0: summary=f"{crit} critical + {high} high risk indicator(s) detected"
    elif high>0: summary=f"{high} high + {med} medium risk indicator(s) detected"
    elif med>0: summary=f"{med} medium risk indicator(s) detected"
    else: summary="Low risk URL — no major indicators found"
    return {"phishing_reasons":reasons,"safe_points":safe_pts,"risk_summary":summary}

def get_severity(result,conf,layer):
    if result=="safe": return "SAFE","#10B981"
    if layer=="blacklist": return "CRITICAL","#FF1744"
    if conf>=95: return "CRITICAL","#FF1744"
    if conf>=85: return "HIGH","#EF4444"
    if conf>=70: return "MEDIUM","#F97316"
    return "LOW","#F59E0B"

def login_required(f):
    @wraps(f)
    def dec(*a,**k):
        if "username" not in session: return redirect(url_for("login_page"))
        return f(*a,**k)
    return dec

# ─── Page routes ─────────────────────────────────────────────────────────────
@app.route("/landing")
def landing():
    if "username" in session: return redirect(url_for("home"))
    return render_template("landing.html")

@app.route("/")
def root():
    if "username" not in session: return redirect(url_for("landing"))
    return redirect(url_for("home"))

@app.route("/login",methods=["GET","POST"])
def login_page():
    if "username" in session: return redirect(url_for("home"))
    error=None
    if request.method=="POST":
        un=request.form.get("username","").strip().lower()
        pw=request.form.get("password","")
        user=get_user(un)
        if not user: error="Account not found."
        elif user["password"]!=hash_pw(pw): error="Incorrect password."
        else:
            session["username"]=un; session["display_name"]=user.get("display_name",un)
            return redirect(url_for("home"))
    return render_template("login.html",error=error)

@app.route("/register",methods=["GET","POST"])
def register_page():
    if "username" in session: return redirect(url_for("home"))
    error=None; success=None
    if request.method=="POST":
        dn=request.form.get("display_name","").strip()
        un=request.form.get("username","").strip().lower()
        em=request.form.get("email","").strip().lower()
        pw=request.form.get("password","")
        cpw=request.form.get("confirm_password","")
        if not all([dn,un,em,pw,cpw]): error="All fields required."
        elif len(un)<3: error="Username ≥ 3 chars."
        elif len(pw)<6: error="Password ≥ 6 chars."
        elif pw!=cpw: error="Passwords don't match."
        elif get_user(un): error=f"'{un}' already taken."
        elif "@" not in em: error="Valid email required."
        else:
            users=load_users()
            users[un]={"username":un,"display_name":dn,"email":em,"password":hash_pw(pw),
                       "created_at":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            save_users(users); success=f"Account created! Welcome, {dn}. Please sign in."
    return render_template("register.html",error=error,success=success)

@app.route("/logout")
def logout(): session.clear(); return redirect(url_for("landing"))

@app.route("/home")
@login_required
def home(): return render_template("index.html",active="home",user=session.get("display_name","User"))

@app.route("/scanner")
@login_required
def scanner(): return render_template("scanner.html",active="scanner",user=session.get("display_name","User"))

@app.route("/analytics")
@login_required
def analytics(): return render_template("analytics.html",active="analytics",user=session.get("display_name","User"))

@app.route("/charts")
@login_required
def charts(): return render_template("charts.html",active="charts",user=session.get("display_name","User"))

@app.route("/history")
@login_required
def history(): return render_template("history.html",active="history",user=session.get("display_name","User"))

@app.route("/blacklist")
@login_required
def blacklist_page(): return render_template("blacklist.html",active="blacklist",user=session.get("display_name","User"))

# ─── Predict ─────────────────────────────────────────────────────────────────
@app.route("/predict",methods=["POST"])
@login_required
def predict():
    data=request.get_json(force=True) or {}
    url=data.get("url","").strip()
    if not url: return jsonify({"error":"No URL"}),400
    if not url.startswith("http"): url="https://"+url
    username=session["username"]

    feats=extract_features(url)
    ssl_r=check_ssl(url)
    domain_age=get_domain_age(url)

    # ── Parse URL once — used by ALL checks below ─────────────────────────────
    _parsed=urlparse(url if url.startswith("http") else "http://"+url)
    _host=(_parsed.hostname or "").lower()
    _parts=_host.split(".")
    _tld="."+_parts[-1] if "." in _host else ""

    # ── Layer 1: Whitelist ────────────────────────────────────────────────────
    if is_whitelisted(url):
        log_user_scan(username,url,"safe",100.0,"whitelist")
        r=generate_reasons(url,feats,100.0,"whitelist",ssl_r,domain_age)
        return jsonify({"url":url,"result":"safe","conf":100.0,"layer":"whitelist","new_bl":False,
            "preds":{n:"Safe" for n in MNAMES.values()},"feats":feats,"ssl":ssl_r,
            "domain_age":domain_age,"sev":"SAFE","sev_c":"#10B981",**r})

    # ── Short URL check ───────────────────────────────────────────────────────
    if _host in SHORT_DOMAINS:
        log_user_scan(username,url,"phishing",72.0,"rule-based")
        _r2=generate_reasons(url,feats,72.0,"rule-based",ssl_r,domain_age)
        _r2["phishing_reasons"].insert(0,{"icon":"🔗","level":"high",
            "text":f"Short URL service ({_host}) hides real destination — cannot verify safety without following the redirect"})
        _r2["risk_summary"]=f"Short URL ({_host}) — real destination unknown. 72% risk score."
        return jsonify({"url":url,"result":"phishing","conf":72.0,"layer":"rule-based",
            "new_bl":False,"preds":{n:"Phishing" for n in MNAMES.values()},
            "feats":feats,"ssl":ssl_r,"domain_age":domain_age,
            "sev":"HIGH","sev_c":"#EF4444",**_r2})

    # ── Free hosting platform abuse check ─────────────────────────────────────
    _hosting_domain=".".join(_parts[-2:]) if len(_parts)>=2 else ""
    _hosting_domain3=".".join(_parts[-3:]) if len(_parts)>=3 else ""

    if _hosting_domain in ABUSED_HOSTING or _hosting_domain3 in ABUSED_HOSTING:
        _subdomain=".".join(_parts[:-2]) if len(_parts)>2 else ""
        _kw_in_sub=any(k in _subdomain for k in PHISHING_KW_HOST)
        _looks_gibberish=len(_subdomain)>10 and _subdomain.replace("-","").isalpha()
        if _kw_in_sub or _looks_gibberish or len(_subdomain)>15:
            _conf=75.0
            log_user_scan(username,url,"phishing",_conf,"rule-based")
            _r=generate_reasons(url,feats,_conf,"rule-based",ssl_r,domain_age)
            _r["phishing_reasons"].insert(0,{"icon":"☁️","level":"high",
                "text":f"Hosted on free platform '{_hosting_domain}' with suspicious subdomain — "
                       f"attackers abuse free hosting (Firebase, Netlify, Vercel) to get valid SSL "
                       f"and avoid domain blacklists"})
            _r["risk_summary"]=f"Suspicious free-hosted site on {_hosting_domain} — 75% risk score."
            return jsonify({"url":url,"result":"phishing","conf":_conf,
                "layer":"rule-based","new_bl":False,
                "preds":{n:"Phishing" for n in MNAMES.values()},
                "feats":feats,"ssl":ssl_r,"domain_age":domain_age,
                "sev":"HIGH","sev_c":"#EF4444",**_r})

    # ── Layer 2: Blacklist ────────────────────────────────────────────────────
    bl,_=is_blacklisted(url)
    if bl:
        log_user_scan(username,url,"phishing",100.0,"blacklist")
        r=generate_reasons(url,feats,100.0,"blacklist",ssl_r,domain_age)
        return jsonify({"url":url,"result":"phishing","conf":100.0,"layer":"blacklist","new_bl":False,
            "preds":{n:"Phishing" for n in MNAMES.values()},"feats":feats,"ssl":ssl_r,
            "domain_age":domain_age,"sev":"CRITICAL","sev_c":"#FF1744",**r})

    # ── Rule-based check ──────────────────────────────────────────────────────
    rule_score=0

    if not url.startswith("https"): rule_score+=10
    if _tld in RISKY_TLDS_SET: rule_score+=25

    _kw_hits=[k for k in PHISHING_KW_HOST if k in _host]
    rule_score+=min(30,len(_kw_hits)*10)
    if len(_kw_hits)>=3: rule_score+=10

    for brand in BRAND_NAMES:
        if brand in _host:
            _is_real=(
                _host==brand+"."+_parts[-1] or
                _host.endswith("."+brand+"."+_parts[-1]) or
                _host==brand+".co."+_parts[-1] or
                _host.endswith("."+brand+".co."+_parts[-1])
            )
            if not _is_real: rule_score+=30
            break

    if _host.count("-")>=3: rule_score+=10
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$",_host): rule_score+=35
    if "@" in url: rule_score+=25
    if len(url)>200: rule_score+=15
    elif len(url)>150: rule_score+=8

    rule_score=min(100,rule_score)

    if rule_score>=70:
        rule_conf=float(rule_score)
        new_bl=False
        _has_ip=bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$",_host))
        if rule_score>=90 and (_has_ip or "@" in url):
            new_bl=add_to_blacklist(url,confidence=rule_conf,source="auto-rule")
        log_user_scan(username,url,"phishing",rule_conf,"rule-based")
        sev,sev_c=get_severity("phishing",rule_conf,"rule-based")
        _r=generate_reasons(url,feats,rule_conf,"rule-based",ssl_r,domain_age)
        return jsonify({"url":url,"result":"phishing","conf":rule_conf,
            "layer":"rule-based","new_bl":new_bl,
            "preds":{n:"Phishing" for n in MNAMES.values()},
            "feats":feats,"ssl":ssl_r,"domain_age":domain_age,
            "sev":sev,"sev_c":sev_c,**_r})

    # ── Layer 3: ML Models ────────────────────────────────────────────────────
    if not MODELS or SCALER is None or not FEAT_NAMES:
        return jsonify({"error":"Models not loaded. Run train_models.py first."}),500
    fdf=pd.DataFrame([feats]).reindex(columns=FEAT_NAMES,fill_value=0)
    fsc=SCALER.transform(fdf)

    pr=MODELS["xgboost"].predict_proba(fdf)[0]
    ph=float(pr[1])
    result="phishing" if ph>=0.70 else "safe"
    conf=round((ph if result=="phishing" else float(pr[0]))*100,2)

    preds={}
    for k,m in MODELS.items():
        try:
            inp=fsc if k in SCALED else fdf
            preds[MNAMES.get(k,k)]="Phishing" if int(m.predict(inp)[0])==1 else "Safe"
        except: preds[MNAMES.get(k,k)]="Error"

    age=domain_age.get("age_days")
    if age is not None and age<14 and result=="safe" and ph>0.60:
        result="phishing"; conf=max(conf,65.0)

    new_bl=False
    if result=="phishing" and ph>=0.88:
        new_bl=add_to_blacklist(url,confidence=conf,source="auto-detected")

    log_user_scan(username,url,result,conf,"ml")
    sev,sev_c=get_severity(result,conf,"ml")
    r=generate_reasons(url,feats,conf,"ml",ssl_r,domain_age)
    return jsonify({"url":url,"result":result,"conf":conf,"layer":"ml","new_bl":new_bl,
        "preds":preds,"feats":feats,"ssl":ssl_r,"domain_age":domain_age,
        "sev":sev,"sev_c":sev_c,**r})

# ─── API routes ───────────────────────────────────────────────────────────────
@app.route("/api/stats")
@login_required
def api_stats():
    try:
        us=get_user_stats(session["username"])
        return jsonify({"today":get_today_stats(),"blacklist_total":get_blacklist_count(),"loaded":LOADED,"user_stats":us})
    except Exception as e:
        return jsonify({"error":str(e),"today":{},"blacklist_total":0,"loaded":LOADED,"user_stats":{"total":0,"phishing":0,"safe":0}}),200

@app.route("/api/model-stats")
@login_required
def api_model_stats(): return jsonify({"accuracies":MODEL_RESULTS,"feature_importances":FEAT_IMP})

@app.route("/api/history")
@login_required
def api_history(): return jsonify(get_user_scans(session["username"],200))

@app.route("/api/history/clear",methods=["POST"])
@login_required
def api_history_clear():
    clear_user_history(session["username"]); return jsonify({"status":"cleared"})

@app.route("/api/charts")
@login_required
def api_charts():
    username=session["username"]; scans=get_user_scans(username,500)
    ph=sum(1 for s in scans if s.get("result")=="phishing")
    sf=sum(1 for s in scans if s.get("result")=="safe")
    bl=sum(1 for s in scans if s.get("detection_layer")=="blacklist")
    wl=sum(1 for s in scans if s.get("detection_layer")=="whitelist")
    ml=sum(1 for s in scans if s.get("detection_layer")=="ml")
    from collections import defaultdict
    dc=defaultdict(lambda:{"phishing":0,"safe":0})
    for s in scans:
        d=(s.get("scanned_at") or "")[:10]
        if d: dc[d][s.get("result","safe")]+=1
    days=sorted(dc.keys())[-14:]
    ranges={"0-20":0,"20-40":0,"40-60":0,"60-80":0,"80-100":0}
    for s in scans:
        c=float(s.get("confidence",0))
        if c<20: ranges["0-20"]+=1
        elif c<40: ranges["20-40"]+=1
        elif c<60: ranges["40-60"]+=1
        elif c<80: ranges["60-80"]+=1
        else: ranges["80-100"]+=1
    return jsonify({"pie":{"phishing":ph,"safe":sf,"total":len(scans)},
        "layer_pie":{"blacklist":bl,"whitelist":wl,"ml":ml},
        "line":{"labels":days,"phishing":[dc[d]["phishing"] for d in days],"safe":[dc[d]["safe"] for d in days]},
        "bar":{"labels":list(ranges.keys()),"values":list(ranges.values())},"total":len(scans)})

@app.route("/api/blacklist")
@login_required
def api_blacklist(): return jsonify(get_blacklist(300))

@app.route("/api/blacklist/add",methods=["POST"])
@login_required
def api_bl_add():
    d=request.get_json(force=True) or {}; url=d.get("url","").strip()
    if url: add_to_blacklist(url,confidence=100.0,source=d.get("source","manual"))
    return jsonify({"status":"added"})

@app.route("/api/blacklist/remove",methods=["POST"])
@login_required
def api_bl_remove():
    url=(request.get_json(force=True) or {}).get("url","").strip()
    if url: remove_from_blacklist(url)
    return jsonify({"status":"removed"})

if __name__=="__main__":
    app.run(debug=True,port=5000,host="0.0.0.0")