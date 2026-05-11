// blacklist_page.js — PhishGuard AI
async function loadBlacklist(){
  try{
    const rows=await fetch("/api/blacklist").then(r=>r.json());
    document.getElementById("blTotal").textContent=rows.length;
    document.getElementById("blAuto").textContent=rows.filter(r=>r.source==="auto-detected").length;
    document.getElementById("blManual").textContent=rows.filter(r=>r.source==="manual").length;

    const tb=document.getElementById("blBody");
    if(!rows.length){
      tb.innerHTML='<tr class="empty-row"><td colspan="6">No blacklisted URLs yet. Phishing detections above 88% confidence are auto-added here.</td></tr>';
      return;
    }

    tb.innerHTML=rows.map(r=>{
      const sc=r.source==="auto-detected"?"color:#EF4444":"color:#9333EA";
      const url=escHtml(r.url||"");
      const domain=escHtml(r.domain||"");
      return `<tr>
        <td>${r.added_at||""}</td>
        <td class="td-url" title="${url}">${url}</td>
        <td style="font-family:var(--mono);font-size:0.72rem;color:#94A3B8">${domain}</td>
        <td style="${sc};font-size:0.72rem;font-weight:700">${r.source||""}</td>
        <td class="td-conf">${r.confidence||0}%</td>
        <td><button class="rm-btn" onclick="removeURL('${url.replace(/'/g,"\\'")}')">🗑 Remove</button></td>
      </tr>`;
    }).join("");
  }catch(e){
    document.getElementById("blBody").innerHTML='<tr class="empty-row"><td colspan="6">Failed to load. Is Flask running?</td></tr>';
  }
}

function escHtml(str){
  return str.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

async function manualAdd(){
  const url=document.getElementById("manualUrl")?.value.trim();
  if(!url){alert("Please enter a URL.");return;}
  try{
    await fetch("/api/blacklist/add",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url,source:"manual"})});
    document.getElementById("manualUrl").value="";
    loadBlacklist();
  }catch(e){alert("Failed to add URL.");}
}

async function removeURL(url){
  if(!confirm("Remove from blacklist?\n"+url)) return;
  try{
    await fetch("/api/blacklist/remove",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url})});
    loadBlacklist();
  }catch(e){alert("Failed to remove URL.");}
}

window.addEventListener("DOMContentLoaded",loadBlacklist);