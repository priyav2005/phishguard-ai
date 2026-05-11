// ── Background orbs ─────────────────────────────────────────────────────────
(function(){
  const c=document.getElementById("bgCanvas");
  if(!c)return;
  const ctx=c.getContext("2d");
  let W,H,ang=0;
  function resize(){W=c.width=window.innerWidth;H=c.height=window.innerHeight;}
  function draw(){
    ctx.clearRect(0,0,W,H);
    const r1=ang*Math.PI/180,r2=(ang+120)*Math.PI/180;
    const o1x=W*0.25+Math.cos(r1)*80,o1y=H*0.40+Math.sin(r1*0.7)*50;
    [[280,10],[180,18],[90,35],[50,55]].forEach(([r,a])=>{
      const g=ctx.createRadialGradient(o1x,o1y,0,o1x,o1y,r);
      g.addColorStop(0,`rgba(99,102,241,${a/100})`);g.addColorStop(1,"transparent");
      ctx.fillStyle=g;ctx.fillRect(0,0,W,H);
    });
    const o2x=W*0.75+Math.cos(r2)*70,o2y=H*0.35+Math.sin(r2*0.8)*45;
    [[230,8],[140,15],[70,28],[40,48]].forEach(([r,a])=>{
      const g=ctx.createRadialGradient(o2x,o2y,0,o2x,o2y,r);
      g.addColorStop(0,`rgba(147,51,234,${a/100})`);g.addColorStop(1,"transparent");
      ctx.fillStyle=g;ctx.fillRect(0,0,W,H);
    });
    ang=(ang+0.4)%360;requestAnimationFrame(draw);
  }
  resize();draw();window.addEventListener("resize",resize);
})();

// ── Threat ticker ────────────────────────────────────────────────────────────
const FEEDS=["⚠  Phishing campaign targeting Indian banking users — SBI, HDFC, ICICI","🔴  New site flagged: secure-paypal-verify-account.tk","⚡  3.4 Billion phishing emails are sent globally every single day","🛡  PhishGuard AI auto-blacklisted 14 new threats in the past hour","⚠  SMS phishing (smishing) wave hitting Jio & Airtel users","🔴  Fake Amazon Great Sale phishing page detected and blocked","⚡  A new phishing website is created every 11 seconds","🛡  XGBoost model maintaining 97.5% accuracy on latest scan batch","⚠  Google Forms used as phishing vector — credential harvesting detected","🔴  Domain squatting: paypa1.com, g00gle.in active campaigns","⚡  SSL mismatches on 5 newly registered suspicious domains","🛡  Auto-blacklist updated — 50+ new domains blocked this week"];
let _ti=0;
function nextTick(){const el=document.getElementById("tickerText");if(el)el.textContent=FEEDS[_ti++%FEEDS.length];}
nextTick();setInterval(nextTick,5000);

// ── Security tips ────────────────────────────────────────────────────────────
const TIPS=["Always verify HTTPS before entering passwords.","IP addresses in URLs are a major phishing red flag.","Urgency + fear = classic phishing tactic. Stay calm.","paypa1.com ≠ paypal.com — check carefully!","Enable 2-Factor Authentication on every account.","Hover links to preview destination before clicking.","Legitimate banks never ask for OTPs via email.","Short URLs can hide malicious destinations — scan first.","Newly registered domains carry higher phishing risk."];
let _tipIdx=0;
function rotateTip(){const el=document.getElementById("sbTip");if(el)el.textContent=TIPS[_tipIdx++%TIPS.length];}
rotateTip();setInterval(rotateTip,7000);

// ── Sidebar toggle ───────────────────────────────────────────────────────────
function toggleSidebar(){
  const sb=document.getElementById("sidebar");
  const ov=document.getElementById("sbOverlay");
  sb?.classList.toggle("mob-open");
  ov?.classList.toggle("open");
}
function closeSidebar(){
  document.getElementById("sidebar")?.classList.remove("mob-open");
  document.getElementById("sbOverlay")?.classList.remove("open");
}

// ── Top stats ────────────────────────────────────────────────────────────────
async function loadTopStats(){
  try{
    const d=await fetch("/api/stats").then(r=>r.json());
    const set=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=v;};
    set("hPhishing",d.today?.phishing_count||0);
    set("hSafe",d.today?.safe_count||0);
    set("hBlacklist",d.blacklist_total||0);
  }catch(_){}
}
loadTopStats();setInterval(loadTopStats,30000);