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

pub fn device_html(issuer: &str, user_code: &str) -> String {
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
*{{box-sizing:border-box}}body{{font-family:system-ui,sans-serif;margin:0;background:#0f172a;color:#e2e8f0;min-height:100vh}}
header{{padding:1rem 2rem;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center}}
main{{padding:2rem;max-width:1100px;margin:0 auto}}
.card{{background:#1e293b;padding:1.5rem;border-radius:12px;margin-bottom:1rem}}
input,button,textarea{{padding:.5rem .75rem;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;margin-right:.5rem;margin-bottom:.5rem}}
button{{background:#3b82f6;border:none;cursor:pointer;color:#fff}}
table{{width:100%;border-collapse:collapse;font-size:.85rem}}
th,td{{text-align:left;padding:.5rem;border-bottom:1px solid #334155}}
pre{{background:#0f172a;padding:1rem;border-radius:8px;overflow:auto;font-size:.8rem;max-height:320px}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:1rem}}
@media(max-width:800px){{.grid{{grid-template-columns:1fr}}}}
</style></head><body>
<header><strong>authsvc Admin</strong><span id="status">Not connected</span></header>
<main>
<div class="card"><h2>Connect</h2>
<input id="token" type="password" placeholder="Bootstrap secret or admin JWT" style="width:320px">
<button onclick="saveToken()">Save</button></div>
<div class="grid">
<div class="card"><h2>User search</h2>
<input id="userQ" placeholder="email prefix" style="width:200px">
<button onclick="searchUsers()">Search</button>
<pre id="usersOut"></pre></div>
<div class="card"><h2>Audit log</h2>
<button onclick="loadAudit()">Refresh</button>
<pre id="auditOut"></pre></div>
</div>
<div class="card"><h2>SAML service providers</h2>
<p style="color:#94a3b8;font-size:.9rem">Register relying parties for SAML IdP mode. IdP metadata: <code>{issuer}/saml/idp/metadata</code></p>
<input id="spName" placeholder="Name" style="width:140px">
<input id="spEntity" placeholder="Entity ID" style="width:220px">
<input id="spAcs" placeholder="ACS URL" style="width:280px">
<label><input type="checkbox" id="spSigned"> Require signed AuthnRequests</label>
<button onclick="createSp()">Add SP</button>
<button onclick="listSps()">Refresh list</button>
<table id="spTable"><thead><tr><th>Name</th><th>Entity ID</th><th>ACS</th><th></th></tr></thead><tbody></tbody></table>
</div>
<div class="card"><h2>Actions</h2>
<button onclick="compliance()">Compliance status</button>
<button onclick="listClients()">List clients</button>
<button onclick="rotateKeys()">Rotate JWT keys</button>
<pre id="out">Results appear here</pre></div>
</main>
<script>
const ISS='{issuer}';
function hdr(){{const t=localStorage.getItem('authsvc_admin');return t?{{Authorization:'Bearer '+t}}:{{}}}}
function saveToken(){{localStorage.setItem('authsvc_admin',document.getElementById('token').value);document.getElementById('status').textContent='Connected'}}
async function compliance(){{const r=await fetch(ISS+'/v1/compliance/status',{{headers:hdr()}});out(await r.json())}}
async function listClients(){{const r=await fetch(ISS+'/v1/clients',{{headers:hdr()}});out(await r.json())}}
async function rotateKeys(){{const r=await fetch(ISS+'/v1/keys/rotate',{{method:'POST',headers:hdr()}});out(await r.json())}}
async function searchUsers(){{const q=document.getElementById('userQ').value;const r=await fetch(ISS+'/v1/users?email='+encodeURIComponent(q),{{headers:hdr()}});document.getElementById('usersOut').textContent=JSON.stringify(await r.json(),null,2)}}
async function loadAudit(){{const r=await fetch(ISS+'/v1/audit/events?limit=50',{{headers:hdr()}});document.getElementById('auditOut').textContent=JSON.stringify(await r.json(),null,2)}}
async function listSps(){{const r=await fetch(ISS+'/v1/saml/service-providers',{{headers:hdr()}});const j=await r.json();const tb=document.querySelector('#spTable tbody');tb.innerHTML='';(j.service_providers||[]).forEach(sp=>{{const tr=document.createElement('tr');tr.innerHTML=`<td>${{sp.name}}</td><td>${{sp.entity_id}}</td><td>${{sp.acs_url}}</td><td><button onclick="delSp('${{sp.id}}')">Delete</button></td>`;tb.appendChild(tr)}})}}
async function createSp(){{const body={{name:document.getElementById('spName').value,entity_id:document.getElementById('spEntity').value,acs_url:document.getElementById('spAcs').value,want_authn_requests_signed:document.getElementById('spSigned').checked}};const r=await fetch(ISS+'/v1/saml/service-providers',{{method:'POST',headers:{{...hdr(),'Content-Type':'application/json'}},body:JSON.stringify(body)}});out(await r.json());listSps()}}
async function delSp(id){{await fetch(ISS+'/v1/saml/service-providers/'+id,{{method:'DELETE',headers:hdr()}});listSps()}}
function out(d){{document.getElementById('out').textContent=JSON.stringify(d,null,2)}}
if(localStorage.getItem('authsvc_admin'))document.getElementById('status').textContent='Connected';
</script></body></html>"#
    )
}
