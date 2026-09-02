function showToast(m){var t=document.getElementById("toast");t.textContent=m;t.style.display="block";setTimeout(function(){t.style.display="none"},3000)}
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
h+='<div class="tenant-card"><div class="tenant-header"><h2>'+t.name+' <span class="badge">'+units.length+' unidades</span></h2>';
h+='<div style="display:flex;gap:10px">';
h+='<button class="btn ed-tenant" data-id="'+t.tenant_id+'" data-name="'+t.name+'" data-slug="'+t.slug+'" data-desc="'+(t.description||'')+'" style="background:rgba(255,255,255,0.2);color:white">Editar</button>';
h+='<button class="btn del-tenant" data-id="'+t.tenant_id+'" style="background:rgba(239,68,68,0.8);color:white">Deletar</button>';
h+='<button class="btn add-unit" data-tid="'+t.tenant_id+'" style="background:rgba(255,255,255,0.3);color:white">+ Unidade</button>';
h+='</div></div><div style="padding:20px">';
if(units.length===0){h+='<div class="empty"><h3>Nenhuma unidade</h3></div>'}else{
h+='<div class="units-grid">';
for(var j=0;j<units.length;j++){var u=units[j];
var lr=await fetch('/api/locations?unit_id='+u.unit_id);var locs=await lr.json();
h+='<div class="unit-card"><div class="unit-header"><h3>'+u.name+' <span class="badge">'+locs.length+'</span></h3>';
h+='<div style="display:flex;gap:5px">';
h+='<button class="btn ed-unit" data-id="'+u.unit_id+'" data-name="'+u.name+'" data-desc="'+(u.description||'')+'" style="background:rgba(255,255,255,0.2);color:white;padding:6px 10px">Editar</button>';
h+='<button class="btn del-unit" data-id="'+u.unit_id+'" style="background:rgba(239,68,68,0.8);color:white;padding:6px 10px">Deletar</button>';
h+='</div></div><div class="locations">';
for(var k=0;k<locs.length;k++){var l=locs[k];
h+='<div class="location-item"><span>'+l.name+'</span><div style="display:flex;gap:5px">';
h+='<button class="btn ed-loc" data-id="'+l.location_id+'" data-name="'+l.name+'" data-desc="'+(l.description||'')+'" style="background:#475569;color:white;padding:4px 8px;font-size:0.75rem">Editar</button>';
h+='<button class="btn del-loc" data-id="'+l.location_id+'" style="background:#ef4444;color:white;padding:4px 8px;font-size:0.75rem">Deletar</button>';
h+='</div></div>'}
h+='<button class="btn add-loc" data-uid="'+u.unit_id+'" style="width:100%;margin-top:10px;background:#1e293b;border:1px dashed #475569;color:#94a3b8">+ Novo Local</button></div></div>'}
h+='</div>';}h+='</div></div>';}
document.getElementById('tree').innerHTML=h||'<div class="empty"><h3>Nenhuma empresa cadastrada</h3></div>';
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
async function saveTenant(){var id=document.getElementById('edit-tenant-id').value;var d={name:document.getElementById('tenant-name').value,slug:document.getElementById('tenant-slug').value||document.getElementById('tenant-name').value.toLowerCase().replace(/[^a-z0-9]/g,'-'),description:document.getElementById('tenant-desc').value};if(!d.name){alert('Nome obrigatorio');return}var url=id?'/api/tenants/'+id:'/api/tenants';await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});closeModal('tenant');showToast('Salvo!');loadTree()}
async function deleteTenant(id){if(!confirm('Deletar empresa?'))return;await fetch('/api/tenants/'+id,{method:'DELETE'});showToast('Deletado!');loadTree()}
async function saveUnit(){var id=document.getElementById('edit-unit-id').value;var d={name:document.getElementById('unit-name').value,description:document.getElementById('unit-desc').value,tenant_id:document.getElementById('unit-tenant-id').value};if(!d.name){alert('Nome obrigatorio');return}var url=id?'/api/units/'+id:'/api/units';await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});closeModal('unit');showToast('Salvo!');loadTree()}
async function deleteUnit(id){if(!confirm('Deletar unidade?'))return;await fetch('/api/units/'+id,{method:'DELETE'});showToast('Deletado!');loadTree()}
async function saveLocation(){var id=document.getElementById('edit-location-id').value;var d={name:document.getElementById('location-name').value,description:document.getElementById('location-desc').value,unit_id:document.getElementById('location-unit-id').value};if(!d.name){alert('Nome obrigatorio');return}var url=id?'/api/locations/'+id:'/api/locations';await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});closeModal('location');showToast('Salvo!');loadTree()}
async function deleteLocation(id){if(!confirm('Deletar local?'))return;await fetch('/api/locations/'+id,{method:'DELETE'});showToast('Deletado!');loadTree()}
document.querySelectorAll('.modal-overlay').forEach(function(m){m.addEventListener('click',function(e){if(e.target===m)m.classList.remove('active')})});
loadTree();
