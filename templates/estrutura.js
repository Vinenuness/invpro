function showToast(m){var t=document.getElementById("toast");t.textContent=m;t.style.display="block";setTimeout(function(){t.style.display="none"},3000)}
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]})}
function openModal(type,d){document.getElementById("modal-"+type).classList.add("active");if(d){document.getElementById("edit-"+type+"-id").value=d.id;document.getElementById(type+"-name").value=d.name;document.getElementById(type+"-desc").value=d.description||"";if(type==="tenant")document.getElementById("tenant-slug").value=d.slug||""}else{document.getElementById("edit-"+type+"-id").value="";document.getElementById(type+"-name").value="";document.getElementById(type+"-desc").value="";if(type==="tenant")document.getElementById("tenant-slug").value=""}}
function openUnitModal(tid){document.getElementById("unit-tenant-id").value=tid;openModal("unit")}
function openLocationModal(uid){document.getElementById("location-unit-id").value=uid;openModal("location")}
function closeModal(type){document.getElementById("modal-"+type).classList.remove("active")}
document.getElementById("btnNovaEmpresa").onclick=function(){openModal("tenant")};
document.getElementById("cancelTenant").onclick=function(){closeModal("tenant")};
document.getElementById("saveTenantBtn").onclick=function(){saveTenant()};
document.getElementById("cancelUnit").onclick=function(){closeModal("unit")};
document.getElementById("saveUnitBtn").onclick=function(){saveUnit()};
document.getElementById("cancelLocation").onclick=function(){closeModal("location")};
document.getElementById("saveLocationBtn").onclick=function(){saveLocation()};
async function loadTree(){
var r=await fetch('/api/tenants');var tenants=await r.json();var h='';
for(var i=0;i<tenants.length;i++){
var t=tenants[i];
var ur=await fetch('/api/units?tenant_id='+t.tenant_id);var units=await ur.json();
var uLabel=(units.length===1)?'1 unidade':units.length+' unidades';
h+='<div class="company"><div class="company-head"><div><h2>'+esc(t.name)+' <span class="pill">'+uLabel+'</span></h2>'+(t.description?'<div class="company-desc">'+esc(t.description)+'</div>':'')+'</div><div class="actions">';
h+='<button class="btn btn-ghost btn-sm ed-tenant" data-id="'+t.tenant_id+'" data-name="'+esc(t.name)+'" data-slug="'+esc(t.slug)+'" data-desc="'+esc(t.description||'')+'">Editar</button>';
h+='<button class="btn btn-danger btn-sm del-tenant" data-id="'+t.tenant_id+'">Excluir</button>';
h+='<button class="btn btn-primary btn-sm add-unit" data-tid="'+t.tenant_id+'">+ Unidade</button>';
h+='</div></div><div class="body">';
if(units.length===0){h+='<div class="empty"><p>Nenhuma unidade ainda. Clique em "+ Unidade" para criar.</p></div>'}else{
h+='<div class="units-grid">';
for(var j=0;j<units.length;j++){var u=units[j];
var lr=await fetch('/api/locations?unit_id='+u.unit_id);var locs=await lr.json();
var lLabel=(locs.length===1)?'1 local':locs.length+' locais';
h+='<div class="unit"><div class="unit-head"><div><h3>'+esc(u.name)+' <span class="pill">'+lLabel+'</span></h3>'+(u.description?'<div class="unit-desc">'+esc(u.description)+'</div>':'')+'</div><div class="actions">';
h+='<button class="btn btn-ghost btn-sm ed-unit" data-id="'+u.unit_id+'" data-name="'+esc(u.name)+'" data-desc="'+esc(u.description||'')+'">Editar</button>';
h+='<button class="btn btn-danger btn-sm del-unit" data-id="'+u.unit_id+'">Excluir</button>';
h+='</div></div><div class="locations">';
for(var k=0;k<locs.length;k++){var l=locs[k];
h+='<div class="loc-row"><div class="loc-info"><div class="loc-name">'+esc(l.name)+'</div>'+(l.description?'<div class="loc-desc">'+esc(l.description)+'</div>':'')+'</div><div class="actions">';
h+='<button class="btn btn-ghost btn-sm ed-loc" data-id="'+l.location_id+'" data-name="'+esc(l.name)+'" data-desc="'+esc(l.description||'')+'">Editar</button>';
h+='<button class="btn btn-danger btn-sm del-loc" data-id="'+l.location_id+'">Excluir</button>';
h+='</div></div>'}
h+='<button class="add-loc" data-uid="'+u.unit_id+'">+ Novo Local</button></div></div>'}
h+='</div>';}
h+='</div></div>';}
document.getElementById('tree').innerHTML=h||'<div class="empty"><h3>Nenhuma empresa cadastrada</h3><p>Clique em "+ Nova Empresa" para comecar.</p></div>';
bindEvents();
}

function bindEvents(){
document.querySelectorAll('.ed-tenant').forEach(function(b){b.onclick=function(){openModal('tenant',{id:this.dataset.id,name:this.dataset.name,slug:this.dataset.slug,description:this.dataset.desc})}});
document.querySelectorAll('.del-tenant').forEach(function(b){b.onclick=function(){deleteTenant(this.dataset.id)}});
document.querySelectorAll('.add-unit').forEach(function(b){b.onclick=function(){openUnitModal(this.dataset.tid)}});
document.querySelectorAll('.ed-unit').forEach(function(b){b.onclick=function(){openModal('unit',{id:this.dataset.id,name:this.dataset.name,description:this.dataset.desc})}});
document.querySelectorAll('.del-unit').forEach(function(b){b.onclick=function(){deleteUnit(this.dataset.id)}});
document.querySelectorAll('.ed-loc').forEach(function(b){b.onclick=function(){openModal('location',{id:this.dataset.id,name:this.dataset.name,description:this.dataset.desc})}});
document.querySelectorAll('.del-loc').forEach(function(b){b.onclick=function(){deleteLocation(this.dataset.id)}});
document.querySelectorAll('.add-loc').forEach(function(b){b.onclick=function(){openLocationModal(this.dataset.uid)}});
}
async function saveTenant(){var id=document.getElementById('edit-tenant-id').value;var d={name:document.getElementById('tenant-name').value.trim(),slug:document.getElementById('tenant-slug').value.trim()||document.getElementById('tenant-name').value.toLowerCase().replace(/[^a-z0-9]/g,'-'),description:document.getElementById('tenant-desc').value.trim()};if(!d.name){alert('Nome obrigatorio');return}var url=id?'/api/tenants/'+id:'/api/tenants';var resp=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});if(!resp.ok){var e=await resp.json().catch(function(){return{}});alert(e.error||'Erro ao salvar');return}closeModal('tenant');showToast('Salvo!');loadTree()}
async function deleteTenant(id){if(!confirm('Excluir esta empresa e todas as unidades/locais vinculados?'))return;await fetch('/api/tenants/'+id,{method:'DELETE'});showToast('Excluido!');loadTree()}
async function saveUnit(){var id=document.getElementById('edit-unit-id').value;var d={name:document.getElementById('unit-name').value.trim(),description:document.getElementById('unit-desc').value.trim(),tenant_id:document.getElementById('unit-tenant-id').value};if(!d.name){alert('Nome obrigatorio');return}var url=id?'/api/units/'+id:'/api/units';var resp=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});if(!resp.ok){var e2=await resp.json().catch(function(){return{}});alert(e2.error||'Erro ao salvar');return}closeModal('unit');showToast('Salvo!');loadTree()}
async function deleteUnit(id){if(!confirm('Excluir esta unidade?'))return;await fetch('/api/units/'+id,{method:'DELETE'});showToast('Excluido!');loadTree()}
async function saveLocation(){var id=document.getElementById('edit-location-id').value;var d={name:document.getElementById('location-name').value.trim(),description:document.getElementById('location-desc').value.trim(),unit_id:document.getElementById('location-unit-id').value};if(!d.name){alert('Nome obrigatorio');return}var url=id?'/api/locations/'+id:'/api/locations';var resp=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});if(!resp.ok){var e3=await resp.json().catch(function(){return{}});alert(e3.error||'Erro ao salvar');return}closeModal('location');showToast('Salvo!');loadTree()}
async function deleteLocation(id){if(!confirm('Excluir este local?'))return;await fetch('/api/locations/'+id,{method:'DELETE'});showToast('Excluido!');loadTree()}
document.querySelectorAll('.modal-overlay').forEach(function(m){m.addEventListener('click',function(e){if(e.target===m)m.classList.remove('active')})});
loadTree();
