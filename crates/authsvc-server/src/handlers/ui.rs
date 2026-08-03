use axum::{
    extract::{Query, State},
    response::Html,
};

use crate::handlers::SharedState;

#[derive(Debug, serde::Deserialize)]
pub struct LoginPageQuery {
    pub login_state: Option<String>,
    pub saml_authn_id: Option<String>,
    pub client_id: Option<String>,
}

pub async fn login_page(
    State(state): State<SharedState>,
    Query(query): Query<LoginPageQuery>,
) -> Html<String> {
    Html(login_html(
        &state.config.issuer,
        query.login_state.as_deref().unwrap_or(""),
        query.saml_authn_id.as_deref().unwrap_or(""),
        query.client_id.as_deref().unwrap_or(""),
    ))
}

pub async fn admin_page(State(state): State<SharedState>) -> Html<String> {
    Html(admin_html(&state.config.issuer))
}

pub fn login_html(issuer: &str, login_state: &str, saml_authn_id: &str, _client_id: &str) -> String {
    let is_saml = !saml_authn_id.is_empty();
    let hidden = if is_saml {
        format!(r#"<input type="hidden" name="saml_authn_id" value="{saml_authn_id}">"#)
    } else {
        format!(r#"<input type="hidden" name="login_state" value="{login_state}">"#)
    };
    let login_endpoint = if is_saml {
        format!("{issuer}/saml/idp/login")
    } else {
        format!("{issuer}/oauth/login")
    };
    let submit_js = if is_saml {
        format!(
            r#"const r=await fetch('{login_endpoint}',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{saml_authn_id:fd.get('saml_authn_id'),email:fd.get('email'),password:fd.get('password')}}),credentials:'include'}});
 if(r.ok){{const t=await r.text();document.open();document.write(t);document.close();return}}
 const j=await r.json().catch(()=>({{}}));
 document.getElementById('err').textContent=j.error_description||j.message||'Login failed';"#
        )
    } else {
        format!(
            r#"const r=await fetch('{login_endpoint}',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{login_state:fd.get('login_state'),email:fd.get('email'),password:fd.get('password')}}),credentials:'include'}});
 const j=await r.json();
 if(r.ok&&j.redirect){{location.href=j.redirect;return}}
 document.getElementById('err').textContent=j.error_description||j.message||'Login failed';"#
        )
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in — authsvc</title>
<style>
*{{box-sizing:border-box}}body{{font-family:system-ui,sans-serif;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f172a;color:#e2e8f0}}
.card{{background:#1e293b;padding:2rem;border-radius:12px;width:100%;max-width:400px;box-shadow:0 25px 50px -12px rgba(0,0,0,.5)}}
h1{{margin:0 0 .5rem;font-size:1.5rem}}p{{color:#94a3b8;margin:0 0 1.5rem;font-size:.9rem}}
label{{display:block;margin-bottom:.35rem;font-size:.85rem;color:#cbd5e1}}
input{{width:100%;padding:.65rem .75rem;margin-bottom:1rem;border:1px solid #334155;border-radius:8px;background:#0f172a;color:#e2e8f0;font-size:1rem}}
button{{width:100%;padding:.75rem;background:#3b82f6;color:#fff;border:none;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer}}
button:hover{{background:#2563eb}}.err{{color:#f87171;margin-top:1rem;font-size:.85rem}}
</style></head><body>
<div class="card">
<h1>Sign in</h1>
<p>Continue to your application</p>
<form id="f">
{hidden}
<label>Email</label><input type="email" name="email" required autocomplete="username">
<label>Password</label><input type="password" name="password" required autocomplete="current-password">
<button type="submit">Sign in</button>
<div class="err" id="err"></div>
</form>
</div>
<script>
document.getElementById('f').onsubmit=async(e)=>{{
 e.preventDefault();
 const fd=new FormData(e.target);
 {submit_js}
}};
</script></body></html>"#
    )
}

pub fn device_html(issuer: &str, user_code: &str, csrf_token: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Device authorization — authsvc</title>
<style>
*{{box-sizing:border-box}}body{{font-family:system-ui,sans-serif;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f172a;color:#e2e8f0}}
.card{{background:#1e293b;padding:2rem;border-radius:12px;width:100%;max-width:400px}}
h1{{margin:0 0 .5rem;font-size:1.5rem}}p{{color:#94a3b8;margin:0 0 1.5rem;font-size:.9rem}}
label{{display:block;margin-bottom:.35rem;font-size:.85rem;color:#cbd5e1}}
input{{width:100%;padding:.65rem .75rem;margin-bottom:1rem;border:1px solid #334155;border-radius:8px;background:#0f172a;color:#e2e8f0;font-size:1rem}}
button{{width:100%;padding:.75rem;background:#3b82f6;color:#fff;border:none;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer}}
</style></head><body>
<div class="card">
<h1>Authorize device</h1>
<p>Enter the code shown on your device, then sign in.</p>
<form method="POST" action="{issuer}/device/approve">
<input type="hidden" name="csrf_token" value="{csrf_token}">
<label>Device code</label><input name="user_code" value="{user_code}" required placeholder="ABCD-EFGH">
<label>Email</label><input type="email" name="email" required>
<label>Password</label><input type="password" name="password" required>
<button type="submit">Authorize</button>
</form></div></body></html>"#
    )
}

pub fn device_success_html() -> String {
    r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Device authorized</title>
<style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f172a;color:#e2e8f0}
.card{background:#1e293b;padding:2rem;border-radius:12px;text-align:center}</style></head>
<body><div class="card"><h1>Device authorized</h1><p>You can return to your device.</p></div></body></html>"#.into()
}

pub fn admin_html(issuer: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>authsvc Admin</title>
<style>
:root{{--bg:#0f172a;--surface:#1e293b;--border:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#3b82f6;--accent-hover:#2563eb;--danger:#ef4444;--ok:#22c55e}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex}}
nav{{width:220px;background:var(--surface);border-right:1px solid var(--border);padding:1.25rem 0;flex-shrink:0}}
nav .brand{{padding:0 1.25rem 1.25rem;font-weight:700;font-size:1.1rem;border-bottom:1px solid var(--border);margin-bottom:.5rem}}
nav a{{display:block;padding:.6rem 1.25rem;color:var(--muted);text-decoration:none;cursor:pointer;font-size:.9rem}}
nav a:hover,nav a.active{{color:var(--text);background:rgba(59,130,246,.12)}}
nav a.active{{border-right:2px solid var(--accent)}}
.content{{flex:1;display:flex;flex-direction:column;min-width:0}}
header{{padding:1rem 1.5rem;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;background:var(--surface)}}
header .status{{font-size:.85rem;padding:.25rem .75rem;border-radius:999px;background:var(--bg);color:var(--muted)}}
header .status.ok{{color:var(--ok)}}
main{{padding:1.5rem;overflow:auto;flex:1}}
.panel{{display:none}}.panel.active{{display:block}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.25rem;margin-bottom:1rem}}
.card h2{{font-size:1rem;margin-bottom:.75rem}}
.card p.hint{{color:var(--muted);font-size:.85rem;margin-bottom:1rem}}
input,button,select{{padding:.5rem .75rem;border-radius:8px;border:1px solid var(--border);background:var(--bg);color:var(--text);font-size:.875rem}}
button{{background:var(--accent);border:none;color:#fff;cursor:pointer;font-weight:500}}
button:hover{{background:var(--accent-hover)}}
button.secondary{{background:transparent;border:1px solid var(--border);color:var(--text)}}
button.danger{{background:var(--danger)}}
.row{{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin-bottom:.75rem}}
table{{width:100%;border-collapse:collapse;font-size:.85rem}}
th{{text-align:left;padding:.6rem .5rem;color:var(--muted);font-weight:500;border-bottom:1px solid var(--border)}}
td{{padding:.6rem .5rem;border-bottom:1px solid var(--border);word-break:break-all}}
.empty{{color:var(--muted);padding:1rem;text-align:center;font-size:.9rem}}
#toast{{position:fixed;bottom:1.5rem;right:1.5rem;padding:.75rem 1.25rem;border-radius:8px;background:var(--surface);border:1px solid var(--border);display:none;z-index:99;font-size:.875rem}}
#toast.err{{border-color:var(--danger);color:#fca5a5}}
#toast.ok{{border-color:var(--ok);color:#86efac}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin-bottom:1rem}}
.stat{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1rem}}
.stat .label{{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}}
.stat .value{{font-size:1.5rem;font-weight:700;margin-top:.25rem}}
pre.raw{{background:var(--bg);padding:1rem;border-radius:8px;overflow:auto;font-size:.75rem;max-height:240px}}
@media(max-width:768px){{nav{{display:none}}body{{flex-direction:column}}}}
</style></head><body>
<nav>
<div class="brand">authsvc</div>
<a class="active" data-panel="dashboard" onclick="showPanel('dashboard',this)">Dashboard</a>
<a data-panel="users" onclick="showPanel('users',this)">Users</a>
<a data-panel="audit" onclick="showPanel('audit',this)">Audit log</a>
<a data-panel="saml" onclick="showPanel('saml',this)">SAML IdP</a>
<a data-panel="settings" onclick="showPanel('settings',this)">Settings</a>
</nav>
<div class="content">
<header>
<span>Admin Console</span>
<span class="status" id="status">Not connected</span>
</header>
<main>
<section id="panel-dashboard" class="panel active">
<div class="stats">
<div class="stat"><div class="label">Users</div><div class="value" id="statUsers">—</div></div>
<div class="stat"><div class="label">Clients</div><div class="value" id="statClients">—</div></div>
<div class="stat"><div class="label">SAML SPs</div><div class="value" id="statSps">—</div></div>
<div class="stat"><div class="label">Audit events</div><div class="value" id="statAudit">—</div></div>
</div>
<div class="card"><h2>Quick actions</h2>
<div class="row">
<button onclick="loadDashboard()">Refresh</button>
<button class="secondary" onclick="compliance()">Compliance status</button>
<button class="secondary" onclick="rotateKeys()">Rotate JWT keys</button>
</div>
<pre class="raw" id="dashOut">Connect with your bootstrap secret or admin JWT in Settings.</pre>
</div>
</section>
<section id="panel-users" class="panel">
<div class="card"><h2>User search</h2>
<div class="row">
<input id="userQ" placeholder="Search by email prefix…" style="flex:1;min-width:200px">
<button onclick="searchUsers()">Search</button>
</div>
<table id="usersTable"><thead><tr><th>Email</th><th>Name</th><th>Status</th><th>Created</th></tr></thead><tbody><tr><td colspan="4" class="empty">Search to find users</td></tr></tbody></table>
</div>
</section>
<section id="panel-audit" class="panel">
<div class="card"><h2>Audit log</h2>
<div class="row"><button onclick="loadAudit()">Refresh</button></div>
<table id="auditTable"><thead><tr><th>Time</th><th>Action</th><th>Resource</th><th>Actor</th></tr></thead><tbody><tr><td colspan="4" class="empty">No events loaded</td></tr></tbody></table>
</div>
</section>
<section id="panel-saml" class="panel">
<div class="card"><h2>SAML service providers</h2>
<p class="hint">IdP metadata: <code>{issuer}/saml/idp/metadata</code></p>
<div class="row">
<input id="spName" placeholder="Name" style="width:120px">
<input id="spEntity" placeholder="Entity ID" style="flex:1;min-width:180px">
<input id="spAcs" placeholder="ACS URL" style="flex:1;min-width:200px">
<label style="font-size:.85rem;color:var(--muted)"><input type="checkbox" id="spSigned"> Signed requests</label>
<button onclick="createSp()">Add SP</button>
</div>
<table id="spTable"><thead><tr><th>Name</th><th>Entity ID</th><th>ACS URL</th><th></th></tr></thead><tbody><tr><td colspan="4" class="empty">No service providers</td></tr></tbody></table>
</div>
</section>
<section id="panel-settings" class="panel">
<div class="card"><h2>Authentication</h2>
<div class="row">
<input id="token" type="password" placeholder="Bootstrap secret or admin JWT" style="flex:1;min-width:280px">
<button onclick="saveToken()">Save token</button>
</div>
<p class="hint">Session stored in an httpOnly cookie (8h TTL). Token is never saved in localStorage.</p>
<div class="row"><button class="secondary" onclick="logout()">Sign out</button></div>
</div>
<div class="card"><h2>API output</h2>
<pre class="raw" id="out">Results appear here</pre>
</div>
</section>
</main>
</div>
<div id="toast"></div>
<script>
const ISS='{issuer}';
const FETCH_OPTS={{credentials:'include'}};
function hdr(){{return{{}}}}
async function connected(){{try{{const j=await fetch(ISS+'/admin/session',FETCH_OPTS).then(r=>r.json());return j.connected}}catch{{return false}}}}
function setStatus(ok){{const el=document.getElementById('status');el.textContent=ok?'Connected':'Not connected';el.className='status'+(ok?' ok':'')}}
function toast(msg,err){{const t=document.getElementById('toast');t.textContent=msg;t.className=err?'err':'ok';t.style.display='block';setTimeout(()=>t.style.display='none',3500)}}
function showPanel(id,el){{document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));document.getElementById('panel-'+id).classList.add('active');document.querySelectorAll('nav a').forEach(a=>a.classList.remove('active'));el.classList.add('active');if(id==='audit')loadAudit();if(id==='saml')listSps();if(id==='dashboard')loadDashboard()}}
async function saveToken(){{try{{const token=document.getElementById('token').value;const r=await fetch(ISS+'/admin/session',{{...FETCH_OPTS,method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{token}})}});if(!r.ok)throw new Error('Invalid token');setStatus(true);toast('Signed in');loadDashboard()}}catch(e){{toast(e.message||'Sign in failed',1)}}}}
async function logout(){{await fetch(ISS+'/admin/session',{{...FETCH_OPTS,method:'DELETE'}});setStatus(false);toast('Signed out')}}
function out(d){{document.getElementById('out').textContent=typeof d==='string'?d:JSON.stringify(d,null,2)}}
async function api(path,opts={{}}){{const r=await fetch(ISS+path,{{...FETCH_OPTS,...opts,headers:{{...hdr(),...(opts.headers||{{}})}}}});const t=await r.text();let j;try{{j=JSON.parse(t)}}catch{{j={{raw:t}}}};if(!r.ok)throw new Error(j.error_description||j.error||r.statusText);return j}}
async function compliance(){{try{{out(await api('/v1/compliance/status'))}}catch(e){{toast(e.message,1)}}}}
async function rotateKeys(){{try{{out(await api('/v1/keys/rotate',{{method:'POST'}}));toast('Keys rotated')}}catch(e){{toast(e.message,1)}}}}
async function searchUsers(){{const q=document.getElementById('userQ').value;if(q.length<2){{toast('Enter at least 2 characters',1);return}}try{{const j=await api('/v1/users?email='+encodeURIComponent(q));const tb=document.querySelector('#usersTable tbody');const users=j.users||[];if(!users.length){{tb.innerHTML='<tr><td colspan="4" class="empty">No users found</td></tr>';return}}tb.innerHTML=users.map(u=>`<tr><td>${{esc(u.email)}}</td><td>${{esc(u.display_name||'—')}}</td><td>${{esc(u.status)}}</td><td>${{esc((u.created_at||'').slice(0,19))}}</td></tr>`).join('');document.getElementById('statUsers').textContent=users.length}}catch(e){{toast(e.message,1)}}}}
async function loadAudit(){{try{{const j=await api('/v1/audit/events?limit=50');const events=j.events||[];const tb=document.querySelector('#auditTable tbody');if(!events.length){{tb.innerHTML='<tr><td colspan="4" class="empty">No audit events</td></tr>';return}}tb.innerHTML=events.map(e=>`<tr><td>${{esc((e.created_at||'').slice(0,19))}}</td><td>${{esc(e.action)}}</td><td>${{esc(e.resource||'—')}}</td><td>${{esc(e.actor_id||'—')}}</td></tr>`).join('');document.getElementById('statAudit').textContent=events.length}}catch(e){{toast(e.message,1)}}}}
async function listSps(){{try{{const j=await api('/v1/saml/service-providers');const sps=j.service_providers||[];const tb=document.querySelector('#spTable tbody');if(!sps.length){{tb.innerHTML='<tr><td colspan="4" class="empty">No service providers</td></tr>';document.getElementById('statSps').textContent='0';return}}tb.innerHTML=sps.map(sp=>`<tr><td>${{esc(sp.name)}}</td><td>${{esc(sp.entity_id)}}</td><td>${{esc(sp.acs_url)}}</td><td><button class="danger" onclick="delSp('${{sp.id}}')">Delete</button></td></tr>`).join('');document.getElementById('statSps').textContent=sps.length}}catch(e){{toast(e.message,1)}}}}
async function createSp(){{try{{const body={{name:document.getElementById('spName').value,entity_id:document.getElementById('spEntity').value,acs_url:document.getElementById('spAcs').value,want_authn_requests_signed:document.getElementById('spSigned').checked}};out(await api('/v1/saml/service-providers',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(body)}}));toast('Service provider added');listSps()}}catch(e){{toast(e.message,1)}}}}
async function delSp(id){{try{{await api('/v1/saml/service-providers/'+id,{{method:'DELETE'}});toast('Deleted');listSps()}}catch(e){{toast(e.message,1)}}}}
async function loadDashboard(){{if(!await connected())return;try{{const clients=await api('/v1/clients');document.getElementById('statClients').textContent=(clients.clients||[]).length;await listSps();await loadAudit()}}catch(e){{/* not connected yet */}}}}
function esc(s){{return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}}
connected().then(ok=>{{if(ok){{setStatus(true);loadDashboard()}}}});
</script></body></html>"#
    )
}
