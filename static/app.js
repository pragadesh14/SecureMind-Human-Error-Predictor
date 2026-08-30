async function loadCharts(){
 try{
  const r=await fetch("/api/stats"); const d=await r.json();
  const t=document.getElementById("trend"), dist=document.getElementById("dist");
  if(t) new Chart(t,{type:"line",data:{labels:d.trend.map(x=>x.date),datasets:[{label:"Risk score",data:d.trend.map(x=>x.score),tension:.35,borderWidth:2,pointRadius:3}]},options:{plugins:{legend:{display:false}},scales:{y:{min:0,max:100,grid:{color:"#1c2842"}},x:{grid:{display:false}}}}});
  if(dist) new Chart(dist,{type:"doughnut",data:{labels:["Low","Medium","High"],datasets:[{data:[d.distribution.LOW,d.distribution.MEDIUM,d.distribution.HIGH],borderWidth:0}]},options:{plugins:{legend:{labels:{color:"#b5c0d5"}}}}});
 }catch(e){console.log("Charts unavailable",e)}
}