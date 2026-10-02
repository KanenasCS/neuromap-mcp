"""Render the graph as a single self-contained, offline HTML map.

Layout: vnet > subnet > resources are nested boxes placed on a grid, and every
other relationship (NSG, public IP, peering, private link, routes) is a line.
Cytoscape.js is embedded, so the file opens with no network access.
"""
from __future__ import annotations

import json
from importlib.resources import files

from .graph import InfraGraph

COLORS = {
    "subscription": "#3b3f5c", "vnet": "#1f6feb", "subnet": "#2d3a55", "nsg": "#f85149",
    "nic": "#8b949e", "vm": "#3fb950", "pip": "#d29922", "routetable": "#a371f7",
    "pe": "#39c5cf", "lb": "#58a6ff", "appgw": "#58a6ff", "firewall": "#ff7b72",
    "bastion": "#7ee787", "vnetgw": "#bc8cff", "natgw": "#e3b341", "asg": "#ffa657",
    "storage": "#2f81f7", "keyvault": "#e3b341", "sql-server": "#db61a2", "sql-db": "#bf4b8a",
    "sql-mi": "#db61a2", "postgres": "#6e9fff", "mysql": "#56b4d3", "cosmos": "#7ce38b",
    "webapp": "#a5d6ff", "appplan": "#6e7681", "aks": "#326ce5", "acr": "#58a6ff", "redis": "#f85149",
    "servicebus": "#d2a8ff", "eventhub": "#d2a8ff", "cognitive": "#ff9bce", "search": "#ffd33d",
    "uami": "#ffa657", "internet": "#ff4d4f", "principal": "#ffa657",
    "fwpolicy": "#ff7b72", "wafpolicy": "#79c0ff", "ipgroup": "#ffa657", "vmss": "#3fb950",
    "lng": "#bc8cff", "ercircuit": "#bc8cff", "gwconnection": "#8957e5", "ip": "#8b949e", "fqdn": "#8b949e",
    "aca-env": "#56d364", "containerapp": "#7ee787", "logicapp": "#d2a8ff", "loganalytics": "#1f6feb",
    "appinsights": "#a371f7", "dce": "#58a6ff", "automation": "#ffa657", "purview": "#39c5cf",
}
HIDDEN_BY_DEFAULT = ["principal", "resourcegroup", "managementgroup", "root"]
EDGE_COLORS = {
    "PROTECTED_BY": "#f85149", "HAS_PUBLIC_IP": "#d29922", "PEERED_WITH": "#1f6feb",
    "CONNECTS_TO": "#39c5cf", "ROUTES_VIA": "#a371f7", "EGRESS_VIA": "#e3b341",
    "OPEN_TO_ALL_NETWORKS": "#ff4d4f", "IP_RULE_ALLOWS": "#ffa657", "VNET_RULE_ALLOWS": "#3fb950",
    "VNET_INTEGRATION": "#a5d6ff", "HAS_ROLE": "#ffa657", "USES_IDENTITY": "#ffa657", "REFERENCES": "#484f58",
    "DNAT_FORWARDS": "#ff7b72", "LB_FORWARDS": "#58a6ff", "APPGW_ROUTES": "#79c0ff", "NEXT_HOP": "#a371f7",
    "HYBRID_CONNECTION": "#bc8cff", "INGRESS_ANY_SOURCE": "#ff4d4f", "INHERITS_FROM": "#ff7b72",
}


def _elements(g: InfraGraph) -> list[dict]:
    parent: dict[str, str] = {}
    hidden: set[tuple[str, str, str]] = set()
    for e in g.edges:
        if e["rel"] == "CONTAINS" and g.nodes[e["src"]]["kind"] == "vnet" and g.nodes[e["dst"]]["kind"] == "subnet":
            parent[e["dst"]] = e["src"]
            hidden.add((e["src"], e["dst"], e["rel"]))
    for e in g.edges:
        if e["rel"] == "IN_SUBNET" and e["src"] not in parent:
            parent[e["src"]] = e["dst"]
            hidden.add((e["src"], e["dst"], e["rel"]))
    for e in g.edges:  # VMs sit in the subnet of their first NIC
        if e["rel"] == "HAS_NIC" and g.nodes[e["src"]]["kind"] == "vm" and e["src"] not in parent:
            if e["dst"] in parent:
                parent[e["src"]] = parent[e["dst"]]
    els, shown = [], set()
    for n in g.nodes.values():
        if n["kind"] == "subscription":
            continue
        shown.add(n["id"])
        els.append({"data": {
            "id": n["id"], "label": n["name"], "kind": n["kind"], "external": not n["in_scan"],
            "color": COLORS.get(n["kind"], "#6e7681"), "parent": parent.get(n["id"]),
            "info": {k: n.get(k) for k in ("kind", "resource_group", "location", "arm_id", "in_scan")} | {"props": n["props"]},
        }})
    for i, e in enumerate(g.edges):
        if (e["src"], e["dst"], e["rel"]) in hidden or e["src"] not in shown or e["dst"] not in shown:
            continue
        els.append({"data": {"id": f"e{i}", "source": e["src"], "target": e["dst"], "rel": e["rel"],
                             "color": EDGE_COLORS.get(e["rel"], "#484f58")}})
    return els


def render_html(g: InfraGraph, title: str = "Azure NeuroMap") -> str:
    cyto = files("neuromap").joinpath("static/cytoscape.min.js").read_text(encoding="utf-8")
    data = json.dumps(_elements(g)).replace("</", "<\\/")
    meta = json.dumps({"collected_at": g.meta.get("collected_at"),
                       "subs": [s.get("name") for s in g.meta.get("subscriptions", [])]}).replace("</", "<\\/")
    return _TEMPLATE.replace("__TITLE__", title).replace("__CYTO__", cyto) \
        .replace("__DATA__", data).replace("__META__", meta).replace("__HIDDEN__", json.dumps(HIDDEN_BY_DEFAULT))


_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--mute:#8b949e;--acc:#58a6ff}
*{box-sizing:border-box}html,body{margin:0;height:100%;background:var(--bg);color:var(--fg);
font:13px/1.45 "Segoe UI",system-ui,-apple-system,sans-serif}
#app{display:grid;grid-template-columns:1fr 380px;height:100%}
#cy{width:100%;height:100%}
header{position:absolute;top:12px;left:12px;display:flex;gap:8px;align-items:center;z-index:5;flex-wrap:wrap;max-width:calc(100% - 420px)}
header h1{font-size:15px;margin:0 8px 0 0;letter-spacing:.3px}
header .meta{color:var(--mute)}
input,button{background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:6px 10px;font:inherit}
button{cursor:pointer}button:hover{border-color:var(--acc)}
aside{background:var(--panel);border-left:1px solid var(--line);overflow:auto;padding:16px}
aside h2{font-size:15px;margin:0 0 4px}aside .k{color:var(--mute);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:12px}
th,td{border-bottom:1px solid var(--line);padding:4px 6px;text-align:left;vertical-align:top;white-space:nowrap}
.scroll{overflow-x:auto;max-width:100%}
th{color:var(--mute);font-weight:600}
.allow{color:#3fb950}.deny{color:#f85149}.def{opacity:.55}
pre{white-space:pre-wrap;word-break:break-all;background:#0d1117;border:1px solid var(--line);border-radius:6px;padding:8px;font-size:11px}
#legend{display:flex;flex-wrap:wrap;gap:6px;margin-top:12px}
#legend span{display:inline-flex;align-items:center;gap:4px;font-size:11px;color:var(--mute);cursor:pointer;user-select:none}
#legend span.off{opacity:.3}#legend i{width:10px;height:10px;border-radius:50%;display:inline-block}
</style></head><body>
<div id="app"><div style="position:relative">
<header><h1>🧠 __TITLE__</h1><span class="meta" id="meta"></span>
<input id="q" placeholder="Search name or IP…" size="24"><button id="fit">Fit</button><button id="relayout">Re-layout</button></header>
<div id="cy"></div></div>
<aside id="side"><div class="k">Details</div><p style="color:var(--mute)">Click any node to see its configuration.
Boxes are VNet → subnet. Lines are NSGs, IPs, peerings, private links, routes, allow rules and references. Red ring = open to all networks.</p>
<div id="legendWrap"><div class="k" style="margin-top:16px">Legend (click to toggle)</div><div id="legend"></div></div></aside></div>
<script>__CYTO__</script>
<script>
const ELS=__DATA__, META=__META__;
document.getElementById('meta').textContent=(META.subs||[]).join(', ')+' · scanned '+(META.collected_at||'?');
const cy=cytoscape({container:document.getElementById('cy'),elements:ELS,wheelSensitivity:.25,
 style:[
  {selector:'node',style:{'background-color':'data(color)','label':'data(label)','color':'#e6edf3','font-size':9,
    'text-valign':'bottom','text-margin-y':3,'width':18,'height':18,'border-width':1,'border-color':'#0d1117'}},
  {selector:'node[kind="nsg"]',style:{'shape':'diamond'}},
  {selector:'node[kind="pip"]',style:{'shape':'star','width':20,'height':20}},
  {selector:'node[kind="vm"]',style:{'shape':'round-rectangle','width':22,'height':16}},
  {selector:'node[?external]',style:{'border-style':'dashed','border-color':'#8b949e','background-opacity':.35}},
  {selector:':parent',style:{'background-opacity':.08,'border-width':1.5,'border-color':'data(color)','text-valign':'top',
    'text-halign':'center','font-size':11,'font-weight':600,'padding':14,'shape':'round-rectangle'}},
  {selector:'node[kind="subscription"]:parent',style:{'border-style':'dotted','font-size':13}},
  {selector:'edge',style:{'width':1.3,'line-color':'data(color)','target-arrow-color':'data(color)',
    'target-arrow-shape':'triangle','arrow-scale':.7,'curve-style':'bezier','opacity':.65}},
  {selector:'edge[rel="PEERED_WITH"]',style:{'width':3,'line-style':'dashed'}},
  {selector:'node[kind="internet"]',style:{'shape':'ellipse','width':44,'height':44,'font-size':12,'font-weight':700,'background-opacity':.9}},
  {selector:'edge[rel="OPEN_TO_ALL_NETWORKS"],edge[rel="INGRESS_ANY_SOURCE"]',style:{'width':2.5,'opacity':.9}},
  {selector:'edge[rel="DNAT_FORWARDS"],edge[rel="LB_FORWARDS"],edge[rel="APPGW_ROUTES"]',style:{'width':2,'opacity':.85}},
  {selector:'edge[rel="HYBRID_CONNECTION"]',style:{'width':3,'line-style':'dashed'}},
  {selector:'edge[rel="REFERENCES"]',style:{'line-style':'dotted','opacity':.45}},
  {selector:'node.open',style:{'border-width':3,'border-color':'#ff4d4f'}},
  {selector:'.faded',style:{'opacity':.08}},
  {selector:'.hl',style:{'opacity':1,'width':2.5,'z-index':9}},
  {selector:'node:selected',style:{'border-width':3,'border-color':'#58a6ff'}}
 ]});
// Deterministic layout: VNets on a grid (most-peered first), subnets side by side,
// resources in a small grid inside each subnet. Everything else floats above what it links to.
function layout(){
 const pos={}, CW=70, RH=58, SUBGAP=70, VGAP=140, ROWGAP=300, MAXW=Math.max(1800, Math.sqrt(cy.nodes().length)*260);
 let cx=0, cy0=0, rowH=0;
 const peers=v=>v.connectedEdges('[rel="PEERED_WITH"]').length;
 cy.nodes('[kind="vnet"]').sort((a,b)=>peers(b)-peers(a)||a.data('label').localeCompare(b.data('label'))).forEach(v=>{
  let sx=cx, vh=RH;
  const subs=v.children(); if(!subs.length){pos[v.id()]={x:cx,y:cy0};}
  subs.sort((a,b)=>a.data('label').localeCompare(b.data('label'))).forEach(sn=>{
   const kids=sn.children().sort((a,b)=>a.data('kind').localeCompare(b.data('kind')));
   const cols=Math.max(1,Math.min(3,Math.ceil(Math.sqrt(kids.length))));
   if(!kids.length) pos[sn.id()]={x:sx,y:cy0};
   kids.forEach((k,i)=>{pos[k.id()]={x:sx+(i%cols)*CW,y:cy0+Math.floor(i/cols)*RH};});
   sx+=Math.max(1,cols)*CW+SUBGAP; vh=Math.max(vh,Math.ceil(Math.max(1,kids.length)/cols)*RH);
  });
  cx=sx+VGAP; rowH=Math.max(rowH,vh);
  if(cx>MAXW){cx=0;cy0+=rowH+ROWGAP;rowH=0;}
 });
 const bottom=cy0+rowH+ROWGAP;
 const center=n=>{const ids=n.isParent()?n.descendants().filter(x=>!x.isParent()).map(x=>x.id()):[n.id()];
  const ps=ids.map(i=>pos[i]).filter(Boolean);return ps.length?{x:ps.reduce((s,p)=>s+p.x,0)/ps.length,y:Math.min(...ps.map(p=>p.y))}:null;};
 const placed=[]; let loose=0;
 // Nearest free slot on the row above the target, so floating labels never overlap.
 const freeSpot=(x,y,down)=>{for(let row=0;row<40;row++){for(let i=0;i<14;i++){
   const dx=(i%2?1:-1)*Math.ceil(i/2)*CW*0.95, p={x:x+dx,y:y+(down?1:-1)*row*RH*0.8};
   if(!placed.some(q=>Math.abs(q.x-p.x)<CW*0.9&&Math.abs(q.y-p.y)<RH*0.7)){placed.push(p);return p;}}}
   const p={x,y:y-12*RH};placed.push(p);return p;};
 const helper=new Set(['resourcegroup','principal','managementgroup','root','internet']);
 const inet=cy.getElementById('internet'); if(inet.length){pos['internet']={x:MAXW/2,y:-420};}
 const floating=cy.nodes().filter(n=>!n.isParent()&&!pos[n.id()]).sort((a,b)=>(helper.has(a.data('kind'))-helper.has(b.data('kind')))||a.data('kind').localeCompare(b.data('kind')));
 for(let pass=0;pass<2;pass++) floating.forEach(n=>{ if(pos[n.id()])return;
  const nb=n.neighborhood('node').filter(x=>helper.has(n.data('kind'))||!helper.has(x.data('kind')));
  const cs=nb.map(center).filter(Boolean);
  if(!cs.length){ if(pass===1){
    if(pos['internet']&&n.neighborhood('#internet').length){pos[n.id()]=freeSpot(pos['internet'].x,pos['internet'].y+110,true);}
    else{pos[n.id()]={x:(loose%20)*CW,y:bottom+Math.floor(loose/20)*RH};loose++;}} return; }
  const x=cs.reduce((s,p)=>s+p.x,0)/cs.length, y=Math.min(...cs.map(p=>p.y));
  pos[n.id()]=freeSpot(x,y-95);
 });
 cy.layout({name:'preset',positions:n=>pos[n.id()]||{x:0,y:bottom},fit:true,padding:40,animate:false}).run();
}
layout();
document.getElementById('fit').onclick=()=>cy.fit(undefined,30);
document.getElementById('relayout').onclick=layout;
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function rulesTable(rules){
 const rows=rules.slice().sort((a,b)=>String(a.direction).localeCompare(String(b.direction))||(a.priority-b.priority)).map(r=>
  `<tr class="${r.default?'def':''}"><td>${esc(r.direction)}</td><td>${r.priority}</td><td class="${(r.access||'').toLowerCase()}">${esc(r.access)}</td>
  <td>${esc(r.protocol)}</td><td>${esc([...r.source,...r.source_asgs.map(a=>'ASG:'+a.split('/').pop())].join(', '))}</td>
  <td>${esc([...r.destination,...r.destination_asgs.map(a=>'ASG:'+a.split('/').pop())].join(', '))}:${esc(r.destination_ports.join(','))}</td><td>${esc(r.name)}</td></tr>`).join('');
 return `<div class="scroll"><table><tr><th>Dir</th><th>Pri</th><th>Act</th><th>Proto</th><th>Source</th><th>Dest:Port</th><th>Name</th></tr>${rows}</table></div>`;
}
function show(n){
 const d=n.data(), info=d.info, p={...info.props}; let html=`<div class="k">${esc(d.kind)}${d.external?' · outside scan':''}</div><h2>${esc(d.label)}</h2>`;
 html+=`<div style="color:var(--mute)">${esc(info.resource_group||'')} ${esc(info.location||'')}</div>`;
 if(p.access){const a=p.access;const bad=['all_networks','all_networks_with_denies'].includes(a.public_endpoint);
  html+=`<div class="k" style="margin-top:12px">Public endpoint</div><div style="font-size:15px;font-weight:700;color:${bad?'#ff4d4f':({unknown:'#d29922',not_evaluated:'#8b949e',restricted:'#58a6ff',gated_by_nsg:'#58a6ff',perimeter_controlled:'#58a6ff'}[a.public_endpoint]||'#3fb950')}">${esc(a.public_endpoint)}</div>`+
   `<ul style="margin:6px 0 0 18px;padding:0">${a.because.map(b=>`<li>${esc(b)}</li>`).join('')}</ul>`+
   (a.unknown.length?`<div class="k" style="margin-top:8px">Unknown</div><ul style="margin:4px 0 0 18px;padding:0">${a.unknown.map(u=>`<li>${esc(u.field)}: ${esc(u.reason)}</li>`).join('')}</ul>`:'')+
   `<div class="k" style="margin-top:8px">Auth</div><pre>${esc(JSON.stringify(a.auth,null,1))}</pre><div class="k">Transport</div><pre>${esc(JSON.stringify(a.transport,null,1))}</pre>`;}
 if(p.rules&&p.rules.length&&p.rules[0].direction!==undefined){html+=`<div class="k" style="margin-top:12px">Security rules</div>`+rulesTable(p.rules);delete p.rules;}
 const tbl=(title,cols,rows)=>`<div class="k" style="margin-top:12px">${title}</div><div class="scroll"><table><tr>${cols.map(c=>`<th>${c}</th>`).join('')}</tr>`+
   rows.map(r=>`<tr>${r.map(v=>`<td>${esc(Array.isArray(v)?v.join(', '):v)}</td>`).join('')}</tr>`).join('')+`</table></div>`;
 const fwr=p.rules&&p.rules.length&&p.rules[0].collection!==undefined?p.rules:(p.classic_rules&&p.classic_rules.length?p.classic_rules:null);
 const TO={dnat:0,network:1,application:2};
 if(fwr){fwr.sort((a,b)=>(TO[a.type]-TO[b.type])||((a.group_priority||0)-(b.group_priority||0))||((a.collection_priority||0)-(b.collection_priority||0))||(a.index-b.index));
  html+=tbl('Firewall rules in processing order (this policy only; use firewall_rules for inherited)',['Type','Group','Coll','Action','Name','Sources','Dest','Ports','→'],
   fwr.map(r=>[r.type,r.group?`${r.group} (${r.group_priority})`:'',`${r.collection} (${r.collection_priority})`,r.action,r.name,
   [...r.sources,...r.source_ip_groups.map(x=>'IPG:'+x.split('/').pop())],[...r.destinations,...r.target_fqdns,...r.destination_fqdns],
   r.ports.length?r.ports:r.protocols,r.translated_address?`${r.translated_address}:${r.translated_port}`:'']));delete p.rules;delete p.classic_rules;}
 if(p.listener_routes){html+=tbl('Listener routes',['Rule','Listener','Port','Paths','Pool','Backend','WAF'],
   p.listener_routes.map(r=>[r.rule,`${r.listener} ${r.listener_protocol||''}`,r.listener_port,r.paths||r.redirect,r.backend_pool,
   `${r.backend_protocol||''}:${r.backend_port||''}`,r.waf?`${r.waf.mode||r.waf.state} (${r.waf.source})`:'']));delete p.listener_routes;}
 if(p.frontends&&p.pools&&Array.isArray(p.rules)){html+=tbl('LB rules',['Kind','Name','Proto','Front','Back'],
   p.rules.map(r=>[r.kind,r.name,r.protocol,r.frontend_port,r.backend_port]));delete p.rules;}
 if(p.routes){html+=`<div class="k" style="margin-top:12px">Routes</div><table><tr><th>Prefix</th><th>Next hop</th><th>IP</th></tr>`+
   p.routes.map(r=>`<tr><td>${esc(r.address_prefix)}</td><td>${esc(r.next_hop_type)}</td><td>${esc(r.next_hop_ip)}</td></tr>`).join('')+`</table>`;delete p.routes;}
 const rel=n.connectedEdges().map(e=>{const o=e.source().id()===n.id()?e.target():e.source();return `<tr><td>${esc(e.data('rel'))}</td><td>${esc(o.data('kind'))}</td><td>${esc(o.data('label'))}</td></tr>`}).join('');
 if(rel)html+=`<div class="k" style="margin-top:12px">Links</div><table>${rel}</table>`;
 html+=`<div class="k" style="margin-top:12px">Properties</div><pre>${esc(JSON.stringify(p,null,2))}</pre>`;
 if(info.arm_id)html+=`<div class="k">Resource ID</div><pre>${esc(info.arm_id)}</pre>`;
 document.getElementById('side').innerHTML=html+document.getElementById('legendWrap').outerHTML;
 bindLegend();
}
cy.on('tap','node',ev=>{const n=ev.target;cy.elements().addClass('faded').removeClass('hl');
 n.closedNeighborhood().union(n.ancestors()).union(n.descendants()).removeClass('faded').addClass('hl');show(n);});
cy.on('tap',ev=>{if(ev.target===cy)cy.elements().removeClass('faded hl');});
document.getElementById('q').addEventListener('input',e=>{const q=e.target.value.trim().toLowerCase();cy.elements().removeClass('faded hl');
 if(!q)return;const hit=cy.nodes().filter(n=>n.data('label').toLowerCase().includes(q)||JSON.stringify(n.data('info').props).includes(q));
 cy.elements().addClass('faded');hit.union(hit.ancestors()).removeClass('faded').addClass('hl');if(hit.length)cy.animate({fit:{eles:hit,padding:80}},{duration:300});});
// legend with kind toggles
const kinds=[...new Set(ELS.filter(e=>e.data.kind).map(e=>e.data.kind))].sort();
const hiddenKinds=new Set(__HIDDEN__);
cy.nodes().forEach(n=>{const a=(n.data('info').props||{}).access;if(a&&['all_networks','all_networks_with_denies'].includes(a.public_endpoint))n.addClass('open');
 if(!n.isParent()&&hiddenKinds.has(n.data('kind')))n.style('display','none');});
const lg=document.getElementById('legend');
kinds.forEach(k=>{const el=ELS.find(e=>e.data.kind===k);lg.insertAdjacentHTML('beforeend',`<span data-k="${k}"><i style="background:${el.data.color}"></i>${k}</span>`);});
function bindLegend(){document.querySelectorAll('#legend span').forEach(s=>{s.classList.toggle('off',hiddenKinds.has(s.dataset.k));s.onclick=()=>{
 const k=s.dataset.k;hiddenKinds.has(k)?hiddenKinds.delete(k):hiddenKinds.add(k);
 cy.nodes().forEach(n=>{if(!n.isParent())n.style('display',hiddenKinds.has(n.data('kind'))?'none':'element')});bindLegend();}});}
bindLegend();
</script></body></html>"""
