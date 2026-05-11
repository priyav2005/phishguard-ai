// scanner.js — PhishGuard AI
// ── Radar ─────────────────────────────────────────────────────────────────────
const rCanvas = document.getElementById("radarCanvas");
const rCtx = rCanvas?.getContext("2d");
let rAng=0, rPulse=0, rPDir=1, rOn=false, rTimer=null;
const rPts = Array.from({length:16},()=>({
  a:Math.random()*360, r:40+Math.random()*80,
  sp:0.5+Math.random()*1.2, sz:2+Math.random()*4, al:80+Math.random()*130
}));

function drawRadar(){
  if(!rCtx) return;
  const W=rCanvas.width, H=rCanvas.height, cx=W/2, cy=H/2, maxR=108;
  rCtx.clearRect(0,0,W,H);
  if(!rOn){
    rCtx.strokeStyle="#2A3F6F"; rCtx.lineWidth=2;
    rCtx.beginPath(); rCtx.arc(cx,cy,44,0,Math.PI*2); rCtx.stroke();
    rCtx.fillStyle="#475569"; rCtx.font="26px Arial"; rCtx.textAlign="center";
    rCtx.fillText("🛡",cx,cy+10); return;
  }
  [[maxR,14],[maxR*0.74,22],[maxR*0.5,34]].forEach(([r,a])=>{
    rCtx.beginPath(); rCtx.arc(cx,cy,r,0,Math.PI*2);
    rCtx.fillStyle=`rgba(99,102,241,${a/100})`; rCtx.fill();
  });
  const rr=rAng*Math.PI/180;
  const sg=rCtx.createRadialGradient(cx,cy,0,cx,cy,maxR);
  sg.addColorStop(0,"rgba(99,102,241,0.5)"); sg.addColorStop(1,"rgba(99,102,241,0)");
  rCtx.save(); rCtx.translate(cx,cy); rCtx.rotate(rr);
  rCtx.beginPath(); rCtx.moveTo(0,0); rCtx.arc(0,0,maxR,-0.55,0); rCtx.closePath();
  rCtx.fillStyle=sg; rCtx.fill(); rCtx.restore();
  [36,66,96].forEach(r=>{
    rCtx.beginPath(); rCtx.arc(cx,cy,r,0,Math.PI*2);
    rCtx.strokeStyle="rgba(42,63,111,0.7)"; rCtx.lineWidth=1;
    rCtx.setLineDash([4,5]); rCtx.stroke(); rCtx.setLineDash([]);
  });
  rCtx.strokeStyle="rgba(42,63,111,0.5)"; rCtx.lineWidth=1; rCtx.setLineDash([4,5]);
  rCtx.beginPath(); rCtx.moveTo(cx-maxR,cy); rCtx.lineTo(cx+maxR,cy); rCtx.stroke();
  rCtx.beginPath(); rCtx.moveTo(cx,cy-maxR); rCtx.lineTo(cx,cy+maxR); rCtx.stroke();
  rCtx.setLineDash([]);
  rPts.forEach(p=>{
    const rad=p.a*Math.PI/180;
    const px=cx+p.r*Math.cos(rad), py=cy+p.r*Math.sin(rad);
    rCtx.beginPath(); rCtx.arc(px,py,p.sz/2,0,Math.PI*2);
    rCtx.fillStyle=`rgba(6,182,212,${p.al/255})`; rCtx.fill();
    p.a=(p.a+p.sp)%360;
  });
  const ex=cx+maxR*Math.cos(rr), ey=cy+maxR*Math.sin(rr);
  rCtx.beginPath(); rCtx.moveTo(cx,cy); rCtx.lineTo(ex,ey);
  rCtx.strokeStyle="#6366F1"; rCtx.lineWidth=2; rCtx.setLineDash([]); rCtx.stroke();
  rPulse+=0.05*rPDir;
  if(rPulse>=1)rPDir=-1; if(rPulse<=0)rPDir=1;
  const pr=12+5*rPulse;
  rCtx.beginPath(); rCtx.arc(cx,cy,pr,0,Math.PI*2);
  rCtx.fillStyle=`rgba(99,102,241,${0.55+0.35*rPulse})`; rCtx.fill();
  rCtx.beginPath(); rCtx.arc(cx,cy,4,0,Math.PI*2);
  rCtx.fillStyle="#F8FAFC"; rCtx.fill();
  rAng=(rAng+2)%360;
}

function startRadar(){ rOn=true; if(!rTimer) rTimer=setInterval(drawRadar,16); }
function stopRadar(){  rOn=false; if(rTimer){clearInterval(rTimer);rTimer=null;} drawRadar(); }
drawRadar();

// ── Steps ─────────────────────────────────────────────────────────────────────
const STEPS=["Initializing threat scanner...","Resolving domain intelligence...",
  "Checking whitelist database...","Querying blacklist database...",
  "Extracting 30 URL features...","Running XGBoost classifier (primary)...",
  "Consulting 7 additional models...","Computing model consensus...",
  "Verifying SSL certificate...","Calculating threat severity...",
  "Generating security report...","Scan complete ✓"];

async function animSteps(totalMs){
  const ms=totalMs/STEPS.length;
  for(let i=0;i<STEPS.length;i++){
    document.getElementById("stepLbl").textContent=STEPS[i];
    document.getElementById("sprogFill").style.width=((i+1)/STEPS.length*100)+"%";
    document.getElementById("topProg").style.width=((i+1)/STEPS.length*100)+"%";
    await new Promise(r=>setTimeout(r,ms));
  }
}

// ── Utils ─────────────────────────────────────────────────────────────────────
function setURL(u){ document.getElementById("urlInput").value=u; }

// ── Scan ──────────────────────────────────────────────────────────────────────
async function scanURL(){
  const url=document.getElementById("urlInput").value.trim();
  if(!url){ document.getElementById("urlInput").focus(); return; }
  const btn=document.getElementById("scanBtn");
  btn.disabled=true; btn.textContent="Scanning...";
  document.getElementById("scanArea").style.display="block";
  document.getElementById("scanArea").scrollIntoView({behavior:"smooth",block:"nearest"});
  document.getElementById("blAlert").style.display="none";
  document.getElementById("topProg").style.width="0%";
  document.getElementById("statusTxt").textContent="";
  startRadar();

  const [res]=await Promise.all([
    fetch("/predict",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url})}),
    animSteps(2800)
  ]).catch(e=>{
    stopRadar(); btn.disabled=false; btn.textContent="🔍 Scan Now";
    document.getElementById("stepLbl").textContent="❌ Error. Is Flask running?";
    return [null];
  });
  if(!res){ return; }

  const d=await res.json();
  stopRadar(); btn.disabled=false; btn.textContent="🔍 Scan Now";
  if(d.error){
    document.getElementById("stepLbl").textContent="❌ "+d.error; return;
  }
  showResult(d);
  if(typeof loadTopStats==="function") loadTopStats();
}

// ── Show result ───────────────────────────────────────────────────────────────
function showResult(d){
  const isP = d.result === "phishing";
  const col  = isP ? "#EF4444" : "#10B981";
  const rc   = document.getElementById("resultCard");
  rc.style.borderColor = col + "66";

  document.getElementById("vEmoji").textContent = isP ? "🚨" : "✅";
  const vt = document.getElementById("vTitle");
  vt.textContent = isP
    ? (d.layer === "blacklist" ? "BLACKLISTED URL" : "PHISHING DETECTED")
    : (d.layer === "whitelist" ? "TRUSTED DOMAIN"  : "SAFE URL");
  vt.style.color = col;
  document.getElementById("vUrl").textContent = d.url;

  // ─── Layer badge ─────────────────────────────────────────────────────────
  const lm = {
    whitelist: ["🛡 WHITELIST",   "#10B981"],
    blacklist: ["⛔ BLACKLIST",   "#EF4444"],
    ml:        ["🤖 ML ANALYSIS", "#6366F1"],
  };
  const [lt, lc] = lm[d.layer] || ["🤖 ML ANALYSIS", "#6366F1"];
  const lb = document.getElementById("layerBadge");
  lb.textContent = lt;
  lb.style.cssText = `color:${lc};background:${lc}22;border:1px solid ${lc}55;border-radius:5px;padding:3px 10px;font-size:11px;font-weight:700;`;

  const sb = document.getElementById("sevBadge");
  sb.textContent = " " + d.sev + " ";
  sb.style.cssText = `color:white;background:${d.sev_c};border:none;border-radius:5px;padding:4px 14px;font-size:12px;font-weight:800;`;

  // ─── Confidence ring ──────────────────────────────────────────────────────
  const conf   = parseFloat(d.conf) || 0;
  const circle = document.getElementById("confCircle");
  circle.style.stroke           = col;
  circle.style.strokeDashoffset = 264 - (264 * conf / 100);

  const cp = document.getElementById("confPct");
  cp.style.color = col;
  let n = 0;
  const t = setInterval(()=>{
    n = Math.min(n + 2, Math.round(conf));
    cp.textContent = n + "%";
    if(n >= Math.round(conf)) clearInterval(t);
  }, 16);

  // ─── Progress bar ─────────────────────────────────────────────────────────
  const cf = document.getElementById("cbarFill");
  cf.style.width      = conf + "%";
  cf.style.background = isP
    ? "linear-gradient(90deg,#EF4444,#FF1744)"
    : "linear-gradient(90deg,#10B981,#06B6D4)";

  if(d.new_bl) document.getElementById("blAlert").style.display = "block";

  // ─── SSL ──────────────────────────────────────────────────────────────────
  const ssl = d.ssl || {};
  const sc  = ssl.valid ? (ssl.days && ssl.days > 30 ? "#10B981" : "#F59E0B") : "#EF4444";
  document.getElementById("sslStatus").innerHTML =
    `<span style="color:${sc};font-weight:700">${ssl.valid ? "✅ Valid SSL" : "❌ No SSL"}</span>`;
  document.getElementById("sslDetails").textContent = ssl.valid
    ? `Issuer: ${ssl.issuer || "?"}\nExpires: ${ssl.expiry || "?"}\nDays: ${ssl.days}\nTLS: ${ssl.version || "?"}`
    : (ssl.error || "SSL check failed");

  // ─── Domain age ───────────────────────────────────────────────────────────
  const da = d.domain_age || {};
  let daColor = "#6B7280", daText = "Unknown";
  if(da.checked){
    if(da.age_days < 30)       { daColor = "#EF4444"; daText = `⚠ Very New (${da.age_days} days)`; }
    else if(da.age_days < 180) { daColor = "#F59E0B"; daText = `⚠ Recent (${da.age_days} days)`;   }
    else                       { daColor = "#10B981"; daText = `✅ Old Domain (${da.age_days} days)`; }
  }
  document.getElementById("domainAgeStatus").innerHTML =
    `<span style="color:${daColor};font-weight:700">${daText}</span>`;
  document.getElementById("domainAgeDetails").textContent = da.checked
    ? `Created: ${da.created || "?"}\nRegistrar: ${da.registrar || "?"}`
    : (da.note || "Domain check failed");

  // ─── Model consensus ──────────────────────────────────────────────────────
  const mg = document.getElementById("modelsGrid");
  mg.innerHTML = "";
  Object.entries(d.preds || {}).forEach(([nm, res]) => {
    const isMP = res.includes("Phishing");
    const pl   = document.createElement("div");
    pl.className = "mpill " + (isMP ? "mpill-ph" : "mpill-sf");
    pl.innerHTML = `
      <span class="mpill-name">${nm.split(" ")[0]}</span>
      <span class="${isMP ? "mpill-res-ph" : "mpill-res-sf"}">${isMP ? "⚠" : "✓"}</span>`;
    mg.appendChild(pl);
  });

  // ─── Reasons / Safe points section ───────────────────────────────────────
  const reasonsSection = document.getElementById("reasonsSection");
  const phishingList   = document.getElementById("phishingReasonsList");
  const safeList       = document.getElementById("safePointsList");
  const reasonsTitle   = document.getElementById("reasonsTitleTxt");

  // Always clear first — prevents stacking on repeated scans
  phishingList.innerHTML = "";
  safeList.innerHTML     = "";
  reasonsSection.style.display = "none";

  const phishingReasons = d.phishing_reasons || [];
  const safePoints      = d.safe_points      || [];

  if(isP && phishingReasons.length > 0){
    // ── PHISHING result ───────────────────────────────────────────────────
    reasonsSection.style.display = "block";
    reasonsTitle.textContent = "⚠️ Why this URL is flagged";

    // Risk summary banner
    if(d.risk_summary){
      phishingList.innerHTML = `
        <div style="margin-bottom:12px;padding:10px 14px;border-radius:8px;
            background:#EF444422;border:1px solid #EF444455;
            color:#FCA5A5;font-weight:600;font-size:13px;">
          ${d.risk_summary}
        </div>`;
    }

    const levelColors = {
      critical: {bg:"#FF174422",border:"#FF174455",text:"#FCA5A5",label:"#FF1744"},
      high:     {bg:"#EF444422",border:"#EF444455",text:"#FCA5A5",label:"#EF4444"},
      medium:   {bg:"#F9731622",border:"#F9731655",text:"#FED7AA",label:"#F97316"},
      low:      {bg:"#F59E0B22",border:"#F59E0B55",text:"#FDE68A",label:"#F59E0B"},
      info:     {bg:"#6366F122",border:"#6366F155",text:"#C7D2FE",label:"#6366F1"},
    };

    phishingList.innerHTML += phishingReasons.map(r => {
      const c = levelColors[r.level] || levelColors.info;
      return `
        <div style="display:flex;align-items:flex-start;gap:10px;padding:10px 14px;
            margin-bottom:8px;border-radius:8px;
            background:${c.bg};border:1px solid ${c.border};">
          <span style="font-size:18px;flex-shrink:0">${r.icon}</span>
          <div style="flex:1">
            <span style="display:inline-block;font-size:10px;font-weight:700;
                color:${c.label};text-transform:uppercase;margin-bottom:3px;
                background:${c.border};padding:1px 7px;border-radius:4px;">
              ${r.level}
            </span>
            <div style="color:${c.text};font-size:13px;line-height:1.5">${r.text}</div>
          </div>
        </div>`;
    }).join("");

  } else if(!isP){
    // ── SAFE result ───────────────────────────────────────────────────────
    let pts = safePoints.length > 0 ? safePoints : [];

    // Auto-generate safe indicators if backend returned none
    if(pts.length === 0){
      if(d.feats?.has_https)                     pts.push({icon:"🔒", text:"Uses HTTPS — connection is encrypted and secure"});
      if(!d.feats?.has_ip)                       pts.push({icon:"✅", text:"No IP address in URL — uses a proper domain name"});
      if(!d.feats?.has_suspicious_keyword)       pts.push({icon:"✅", text:"No suspicious keywords detected in the URL"});
      if(da.checked && da.age_days >= 180)       pts.push({icon:"📅", text:`Domain is ${da.age_days} days old (registered ${da.created || "?"}) — well-established domain`});
      if(ssl.valid && ssl.days && ssl.days > 30) pts.push({icon:"🔐", text:`Valid SSL certificate from ${ssl.issuer || "?"} — expires ${ssl.expiry || "?"}`});
      if(pts.length === 0)                       pts.push({icon:"✅", text:"No phishing indicators detected — URL appears safe"});
    }

    reasonsSection.style.display = "block";
    reasonsTitle.textContent = "✅ Why this URL appears safe";

    // Safe summary banner
    phishingList.innerHTML = `
      <div style="margin-bottom:12px;padding:10px 14px;border-radius:8px;
          background:#10B98122;border:1px solid #10B98155;
          color:#6EE7B7;font-weight:600;font-size:13px;">
        ✅ No significant risk indicators detected — this URL appears safe.
      </div>`;

    // Safe point cards
    safeList.innerHTML = pts.map(p => `
      <div style="display:flex;align-items:flex-start;gap:10px;padding:10px 14px;
          margin-bottom:8px;border-radius:8px;
          background:#10B98115;border:1px solid #10B98133;">
        <span style="font-size:18px;flex-shrink:0">${p.icon}</span>
        <div style="color:#6EE7B7;font-size:13px;line-height:1.5">${p.text}</div>
      </div>`
    ).join("");
  }

  // ─── Key URL features ─────────────────────────────────────────────────────
  const fl = document.getElementById("featsList");
  fl.innerHTML = "";
  const keys = [
    ["url_length",              "URL Length"],
    ["has_https",               "HTTPS"],
    ["has_ip",                  "IP Addr"],
    ["num_dots",                "Dots"],
    ["num_subdomains",          "Subdomains"],
    ["has_suspicious_keyword",  "Susp. KW"],
    ["digit_ratio",             "Digit %"],
    ["num_at",                  "@ Symbol"]
  ];
  keys.forEach(([k, lb3]) => {
    const val = d.feats?.[k];
    if(val === undefined) return;
    const bad = (k === "has_ip"                 && val === 1) ||
                (k === "has_suspicious_keyword"  && val === 1) ||
                (k === "has_https"               && val === 0);
    const disp = typeof val === "number" && val > 0 && val < 1
      ? val.toFixed(3)
      : String(val);
    fl.innerHTML += `
      <div class="feat-row">
        <span class="feat-name">${lb3}</span>
        <span class="feat-val ${bad ? "danger" : ""}">${disp}</span>
      </div>`;
  });

  document.getElementById("stepLbl").textContent = "✅ Scan complete";
}