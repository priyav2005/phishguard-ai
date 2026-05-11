// history.js — PhishGuard AI (per-user history)
let allRows=[], currentFilter="all";

async function loadHistory(){
  try{
    allRows=await fetch("/api/history").then(r=>r.json());
    render();
  }catch(e){
    document.getElementById("histBody").innerHTML='<tr class="empty-row"><td colspan="5">Failed to load. Is Flask running?</td></tr>';
  }
}

function render(){
  const fil = currentFilter==="all" ? allRows
    : currentFilter==="blacklist" ? allRows.filter(r=>r.detection_layer==="blacklist")
    : currentFilter==="whitelist" ? allRows.filter(r=>r.detection_layer==="whitelist")
    : allRows.filter(r=>r.result===currentFilter);

  document.getElementById("recCount").textContent=`${fil.length} / ${allRows.length} records`;
  const tb=document.getElementById("histBody");

  if(!fil.length){
    tb.innerHTML=`<tr class="empty-row"><td colspan="5">No records found. <a href="/scanner" style="color:#6366F1;font-weight:700">Scan some URLs →</a></td></tr>`;
    return;
  }

  const lmap={
    blacklist:["⛔ BLACKLIST","td-bl"],
    whitelist:["🛡 WHITELIST","td-wl"],
    ml:       ["🤖 ML","td-ml"]
  };

  tb.innerHTML=fil.map(r=>{
    const [lt,lc]=lmap[r.detection_layer||"ml"]||lmap.ml;
    return `<tr>
      <td>${r.scanned_at||""}</td>
      <td class="td-url" title="${r.url||""}">${r.url||""}</td>
      <td class="${lc}">${lt}</td>
      <td class="${r.result==="phishing"?"td-ph":"td-sf"}">${(r.result||"").toUpperCase()}</td>
      <td class="td-conf">${r.confidence||0}%</td>
    </tr>`;
  }).join("");
}

function filterBy(f,btn){
  currentFilter=f;
  document.querySelectorAll(".fbtn").forEach(b=>b.classList.remove("active"));
  btn.classList.add("active");
  render();
}

function clearHistory(){
  document.getElementById("clearModal").style.display="flex";
}
function closeClearModal(){
  document.getElementById("clearModal").style.display="none";
}
async function confirmClear(){
  try{
    await fetch("/api/history/clear",{method:"POST"});
    closeClearModal();
    allRows=[];
    render();
  }catch(e){
    alert("Failed to clear history.");
    closeClearModal();
  }
}

window.addEventListener("DOMContentLoaded",loadHistory);