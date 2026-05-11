// analytics.js — PhishGuard AI
async function loadAnalytics(){
  try{
    const d=await fetch("/api/model-stats").then(r=>r.json());
    if(!d.accuracies||Object.keys(d.accuracies).length===0){
      document.getElementById("noModels").style.display="block";
      ["accCards","accBarsCard","featImpCard"].forEach(id=>{
        const el=document.getElementById(id); if(el) el.style.display="none";
      }); return;
    }
    const sorted=Object.entries(d.accuracies).sort((a,b)=>b[1]-a[1]);
    // Accuracy cards
    const colors=["#10B981","#6366F1","#06B6D4","#9333EA","#F97316","#F59E0B","#94A3B8","#64748B"];
    document.getElementById("accCards").innerHTML=sorted.map(([nm,acc],i)=>{
      const col=colors[i]||"#94A3B8";
      const pct=Math.max(0,((acc-75)/25)*100);
      return`<div class="acc-card" style="border-top:3px solid ${col}">
        <div class="acc-rank" style="color:${col}">${i===0?"":"#"+(i+1)}</div>
        <div class="acc-model">${nm}</div>
        <div class="acc-pct" style="color:${col}">${acc}%</div>
        <div class="acc-track"><div class="acc-fill" style="width:${pct}%;background:${col}"></div></div>
      </div>`;
    }).join("");
    // Accuracy bars
    document.getElementById("accBars").innerHTML=sorted.map(([nm,acc],i)=>{
      const col=acc>=96?"#10B981":acc>=92?"#6366F1":"#06B6D4";
      return`<div class="bar-row">
        <div class="bar-label">${nm}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${acc}%;background:linear-gradient(90deg,${col},#9333EA)"></div></div>
        <div class="bar-val" style="color:${col}">${acc}%</div>
      </div>`;
    }).join("");
    // Feature importance
    if(d.feature_importances){
      document.getElementById("featBars").innerHTML=Object.entries(d.feature_importances).map(([feat,imp])=>{
        const pct=parseFloat((imp*100).toFixed(2)); const barW=Math.min(100,pct*6);
        return`<div class="bar-row">
          <div class="bar-label" style="font-family:var(--mono);font-size:0.72rem;color:var(--text2)">${feat.replace(/_/g," ")}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${barW}%;background:linear-gradient(90deg,#7C3AED,#9333EA)"></div></div>
          <div class="bar-val" style="color:#C084FC">${pct}%</div>
        </div>`;
      }).join("");
    }
  }catch(e){console.warn("Analytics error:",e);}
}
window.addEventListener("DOMContentLoaded",loadAnalytics);