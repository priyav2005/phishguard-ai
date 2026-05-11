// radar.js — Reusable radar canvas animation
function startRadar(canvasId) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  let ang = 0, pulse = 0, pDir = 1;
  const pts = Array.from({length:20}, () => ({
    a: Math.random()*360, r: 40+Math.random()*130,
    sp: 0.3+Math.random()*1.0, sz: 1.5+Math.random()*4,
    al: 60+Math.random()*140
  }));

  function resize() {
    canvas.width  = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
  }
  resize();
  window.addEventListener("resize", resize);

  function draw() {
    const W = canvas.width, H = canvas.height;
    const cx = W / 2, cy = H / 2;
    const maxR = Math.min(W, H) * 0.42;
    ctx.clearRect(0, 0, W, H);

    // BG glow rings
    [[1.0,10],[0.75,18],[0.5,28],[0.28,42]].forEach(([f,a]) => {
      ctx.beginPath(); ctx.arc(cx,cy,maxR*f,0,Math.PI*2);
      ctx.fillStyle=`rgba(99,102,241,${a/100})`; ctx.fill();
    });

    // Radar sweep (conical via arc approximation)
    const sweepAng = ang * Math.PI / 180;
    const g = ctx.createRadialGradient(cx,cy,0,cx,cy,maxR);
    g.addColorStop(0,"rgba(99,102,241,0.55)");
    g.addColorStop(1,"rgba(99,102,241,0)");
    ctx.save();
    ctx.translate(cx,cy); ctx.rotate(sweepAng);
    ctx.beginPath(); ctx.moveTo(0,0);
    ctx.arc(0,0,maxR,-0.55,0);
    ctx.closePath(); ctx.fillStyle=g; ctx.fill();
    ctx.restore();

    // Grid rings
    [0.28,0.5,0.75,1.0].forEach(f => {
      ctx.beginPath(); ctx.arc(cx,cy,maxR*f,0,Math.PI*2);
      ctx.strokeStyle="rgba(42,63,111,0.6)"; ctx.lineWidth=1;
      ctx.setLineDash([4,6]); ctx.stroke(); ctx.setLineDash([]);
    });

    // Crosshairs
    ctx.strokeStyle="rgba(42,63,111,0.5)"; ctx.lineWidth=1; ctx.setLineDash([4,6]);
    ctx.beginPath(); ctx.moveTo(cx-maxR,cy); ctx.lineTo(cx+maxR,cy); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(cx,cy-maxR); ctx.lineTo(cx,cy+maxR); ctx.stroke();
    ctx.setLineDash([]);

    // Particles
    pts.forEach(pt => {
      const r = pt.a * Math.PI/180;
      const px = cx + pt.r*Math.cos(r), py = cy + pt.r*Math.sin(r);
      ctx.beginPath(); ctx.arc(px,py,pt.sz/2,0,Math.PI*2);
      ctx.fillStyle=`rgba(6,182,212,${pt.al/255})`; ctx.fill();
      pt.a = (pt.a + pt.sp) % 360;
    });

    // Sweep line
    const ex = cx + maxR*Math.cos(sweepAng), ey = cy + maxR*Math.sin(sweepAng);
    ctx.beginPath(); ctx.moveTo(cx,cy); ctx.lineTo(ex,ey);
    ctx.strokeStyle="#6366F1"; ctx.lineWidth=2; ctx.setLineDash([]); ctx.stroke();

    // Center pulse
    pulse += 0.05*pDir;
    if(pulse>=1)pDir=-1; if(pulse<=0)pDir=1;
    const pr = 10+5*pulse;
    ctx.beginPath(); ctx.arc(cx,cy,pr,0,Math.PI*2);
    ctx.fillStyle=`rgba(99,102,241,${0.55+0.35*pulse})`; ctx.fill();
    ctx.beginPath(); ctx.arc(cx,cy,4,0,Math.PI*2);
    ctx.fillStyle="#F8FAFC"; ctx.fill();

    ang = (ang + 1.5) % 360;
    requestAnimationFrame(draw);
  }
  draw();
}