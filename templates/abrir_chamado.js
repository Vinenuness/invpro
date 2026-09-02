fetch("/api/public/tenants").then(r=>r.json()).then(ts=>{
var s=document.getElementById("fT");s.innerHTML="";
ts.forEach(t=>{var o=document.createElement("option");o.value=t.tenant_id;o.textContent=t.name;s.appendChild(o)});
s.onchange();
});
document.getElementById("fT").onchange=function(){
var tid=this.value,ug=document.getElementById("UG"),lg=document.getElementById("LG");
if(!tid){ug.style.display="none";lg.style.display="none";return}
fetch("/api/public/units?tenant_id="+tid).then(r=>r.json()).then(us=>{
ug.style.display="block";var sel=ug.querySelector("select");
if(!us.length){sel.innerHTML='<option value="">Nenhuma unidade</option>';lg.style.display="none";return}
var h='<option value="">Selecione...</option>';
us.forEach(u=>{h+='<option value="'+u.unit_id+'">'+u.name+'</option>'});
h+='<option value="__new_unit__">+ Criar nova unidade...</option>';
sel.innerHTML=h;
// fU.onchange is already wired below
});
};
document.getElementById("fU").onchange=function(){loadLocations(this.value);};
function loadLocations(uid){lg=document.getElementById("LG");
if(!uid||uid==="__new_unit__"){lg.style.display="none";return}
fetch("/api/public/locations?unit_id="+uid).then(r=>r.json()).then(ls=>{
lg.style.display="block";var sel=lg.querySelector("select");
if(!ls.length){sel.innerHTML='<option value="">Nenhum local</option><option value="__new_loc__">+ Criar novo local...</option>';sel.onchange=function(){if(this.value==="__new_loc__"){createLocationInline(uid);}};return}
var h='<option value="">Selecione...</option>';
ls.forEach(l=>{h+='<option value="'+l.location_id+'">'+l.name+'</option>'});
h+='<option value="__new_loc__">+ Criar novo local...</option>';
sel.innerHTML=h;
sel.onchange=function(){if(this.value==="__new_loc__"){createLocationInline(uid);}};
});
};
function createUnitInline(tid){var name=prompt("Nome da nova unidade:");if(!name||!name.trim())return;fetch("/api/units",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:name.trim(),description:"",tenant_id:tid})}).then(r=>r.json()).then(d=>{if(d.ok){document.getElementById("fT").onchange();}else{alert(d.error||"Erro");}});}
function createLocationInline(uid){var name=prompt("Nome do novo local:");if(!name||!name.trim())return;fetch("/api/locations",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:name.trim(),description:"",unit_id:uid})}).then(r=>r.json()).then(d=>{if(d.ok){document.getElementById("fU").onchange();}else{alert(d.error||"Erro");}});}
function sub(){var n=document.getElementById("fN").value.trim(),t=document.getElementById("fT2").value.trim(),d=document.getElementById("fD").value.trim();if(!n||!t||!d){alert("Preencha nome, titulo e descricao");return}var btn=document.querySelector(".bts");btn.disabled=true;btn.textContent="Enviando...";var p={title:t,tenant_id:parseInt(document.getElementById("fT").value),description:d,priority:document.getElementById("fP").value,created_by:n,email:document.getElementById("fE").value.trim()||null};var uisel=document.getElementById("UG").querySelector("select");var lsel=document.getElementById("LG").querySelector("select");if(uisel&&uisel.value&&uisel.value.indexOf("__")!==0)p.unit_id=parseInt(uisel.value);if(lsel&&lsel.value&&lsel.value.indexOf("__")!==0)p.location_id=parseInt(lsel.value);fetch("/api/tickets/public",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(p)}).then(r=>r.json()).then(d=>{if(d.ok){document.getElementById("fc").style.display="none";document.getElementById("SC").style.display="block"}else{alert(d.error||"Erro");btn.disabled=false;btn.textContent="Enviar Chamado"}}).catch(()=>{alert("Erro de conexao");btn.disabled=false;btn.textContent="Enviar Chamado"});}
function resetForm(){document.getElementById("fN").value="";document.getElementById("fE").value="";document.getElementById("fT2").value="";document.getElementById("fD").value="";document.getElementById("fP").value="medium";document.getElementById("fT").selectedIndex=0;document.getElementById("UG").style.display="none";document.getElementById("LG").style.display="none";document.getElementById("fc").style.display="block";document.getElementById("SC").style.display="none";var btn=document.querySelector(".bts");btn.disabled=false;btn.textContent="Enviar Chamado";}