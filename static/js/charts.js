// charts.js — PhishGuard AI Charts Page
let pieChart=null, layerPieChart=null, lineChart=null, barChart=null;

const COLORS = {
  indigo:"#6366F1", purple:"#9333EA", cyan:"#06B6D4",
  green:"#10B981",  red:"#EF4444",    orange:"#F97316",
  yellow:"#F59E0B", bg2:"#0F1528",    border:"#1E2D50",
  white:"#F8FAFC",  text2:"#94A3B8",
};

Chart.defaults.color = COLORS.text2;
Chart.defaults.borderColor = COLORS.border;
Chart.defaults.font.family = "'Inter', system-ui, sans-serif";

function destroyAll() {
  [pieChart,layerPieChart,lineChart,barChart].forEach(c=>c?.destroy());
  pieChart=layerPieChart=lineChart=barChart=null;
}

async function loadCharts() {
  try {
    const d = await fetch("/api/charts").then(r=>r.json());

    if(d.total === 0) {
      document.getElementById("noDataMsg").style.display="block";
      document.getElementById("chartStats").style.display="none";
      document.getElementById("chartsContainer").style.display="none";
      return;
    }

    document.getElementById("noDataMsg").style.display="none";
    document.getElementById("chartStats").style.display="flex";
    document.getElementById("chartsContainer").style.display="flex";

    // Summary stats
    document.getElementById("cTotal").textContent = d.total;
    document.getElementById("cPhish").textContent = d.pie.phishing;
    document.getElementById("cSafe").textContent  = d.pie.safe;
    const rate = d.total > 0 ? Math.round(d.pie.phishing/d.total*100) : 0;
    document.getElementById("cRate").textContent  = rate+"%";

    destroyAll();

    // ── PIE: Phishing vs Safe ──────────────────────────────────────────────
    pieChart = new Chart(document.getElementById("pieChart"), {
      type: "doughnut",
      data: {
        labels: ["Phishing", "Safe"],
        datasets: [{
          data: [d.pie.phishing, d.pie.safe],
          backgroundColor: ["#EF4444","#10B981"],
          borderColor: ["#FF1744","#06B6D4"],
          borderWidth: 2,
          hoverOffset: 8,
        }]
      },
      options: {
        responsive:true, maintainAspectRatio:true,
        cutout:"65%",
        plugins:{
          legend:{position:"bottom",labels:{color:COLORS.text2,padding:18,font:{size:13,weight:"600"}}},
          tooltip:{
            backgroundColor:"#161F35",borderColor:COLORS.border,borderWidth:1,
            titleColor:COLORS.white,bodyColor:COLORS.text2,padding:12,cornerRadius:10,
            callbacks:{label:ctx=>`  ${ctx.label}: ${ctx.parsed} URLs (${Math.round(ctx.parsed/d.total*100)}%)`}
          }
        }
      }
    });

    // ── PIE: Detection Layer ───────────────────────────────────────────────
    layerPieChart = new Chart(document.getElementById("layerPieChart"), {
      type: "doughnut",
      data: {
        labels: ["ML Analysis","Blacklist","Whitelist"],
        datasets: [{
          data: [d.layer_pie.ml, d.layer_pie.blacklist, d.layer_pie.whitelist],
          backgroundColor: ["#6366F1","#EF4444","#10B981"],
          borderColor: ["#818CF8","#FF1744","#34D399"],
          borderWidth: 2, hoverOffset: 8,
        }]
      },
      options: {
        responsive:true, maintainAspectRatio:true, cutout:"65%",
        plugins:{
          legend:{position:"bottom",labels:{color:COLORS.text2,padding:18,font:{size:13,weight:"600"}}},
          tooltip:{
            backgroundColor:"#161F35",borderColor:COLORS.border,borderWidth:1,
            titleColor:COLORS.white,bodyColor:COLORS.text2,padding:12,cornerRadius:10,
          }
        }
      }
    });

    // ── LINE: Scans per day ────────────────────────────────────────────────
    const labels = d.line.labels.length ? d.line.labels : ["No data"];
    lineChart = new Chart(document.getElementById("lineChart"), {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "Phishing Detected",
            data: d.line.phishing,
            borderColor: "#EF4444",
            backgroundColor: "rgba(239,68,68,0.12)",
            borderWidth: 2.5,
            pointBackgroundColor: "#EF4444",
            pointRadius: 5, pointHoverRadius: 7,
            tension: 0.4, fill: true,
          },
          {
            label: "Safe URLs",
            data: d.line.safe,
            borderColor: "#10B981",
            backgroundColor: "rgba(16,185,129,0.10)",
            borderWidth: 2.5,
            pointBackgroundColor: "#10B981",
            pointRadius: 5, pointHoverRadius: 7,
            tension: 0.4, fill: true,
          }
        ]
      },
      options: {
        responsive:true, maintainAspectRatio:true,
        interaction:{mode:"index",intersect:false},
        scales:{
          x:{
            grid:{color:"rgba(30,45,80,0.5)"},
            ticks:{color:COLORS.text2,font:{size:11}},
          },
          y:{
            beginAtZero:true,
            grid:{color:"rgba(30,45,80,0.5)"},
            ticks:{color:COLORS.text2,font:{size:11},stepSize:1},
          }
        },
        plugins:{
          legend:{position:"top",labels:{color:COLORS.text2,padding:16,font:{size:13,weight:"600"}}},
          tooltip:{
            backgroundColor:"#161F35",borderColor:COLORS.border,borderWidth:1,
            titleColor:COLORS.white,bodyColor:COLORS.text2,padding:12,cornerRadius:10,
          }
        }
      }
    });

    // ── BAR: Confidence distribution ───────────────────────────────────────
    barChart = new Chart(document.getElementById("barChart"), {
      type: "bar",
      data: {
        labels: d.bar.labels,
        datasets: [{
          label: "Number of Scans",
          data: d.bar.values,
          backgroundColor: [
            "rgba(239,68,68,0.7)","rgba(249,115,22,0.7)","rgba(245,158,11,0.7)",
            "rgba(16,185,129,0.7)","rgba(99,102,241,0.8)"
          ],
          borderColor: ["#EF4444","#F97316","#F59E0B","#10B981","#6366F1"],
          borderWidth: 2,
          borderRadius: 8,
          borderSkipped: false,
        }]
      },
      options: {
        responsive:true, maintainAspectRatio:true,
        scales:{
          x:{
            grid:{color:"rgba(30,45,80,0.5)"},
            ticks:{color:COLORS.text2,font:{size:12,weight:"600"}},
            title:{display:true,text:"Confidence Score Range (%)",color:COLORS.text2,font:{size:12}},
          },
          y:{
            beginAtZero:true,
            grid:{color:"rgba(30,45,80,0.5)"},
            ticks:{color:COLORS.text2,font:{size:11},stepSize:1},
            title:{display:true,text:"Number of Scans",color:COLORS.text2,font:{size:12}},
          }
        },
        plugins:{
          legend:{display:false},
          tooltip:{
            backgroundColor:"#161F35",borderColor:COLORS.border,borderWidth:1,
            titleColor:COLORS.white,bodyColor:COLORS.text2,padding:12,cornerRadius:10,
            callbacks:{label:ctx=>`  ${ctx.parsed.y} scans in this confidence range`}
          }
        }
      }
    });

  } catch(e) {
    console.error("Charts error:", e);
    document.getElementById("noDataMsg").style.display="block";
    document.getElementById("noDataMsg").querySelector(".no-data-sub").textContent="Failed to load chart data. Please try again.";
  }
}

window.addEventListener("DOMContentLoaded", loadCharts);