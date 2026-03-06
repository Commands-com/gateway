package oauth

import (
	"html"
	"sort"
	"strings"
)

func renderDemoLogin(req authorizeRequest) string {
	hidden := authorizeHiddenInputs(req)
	return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><title>Sign In — Commands Gateway</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<style>
:root { --bg:#0f1117; --surface:#1a1d27; --border:#2e3345; --text:#e1e4ed; --text2:#8b91a5; --accent:#6c8cff; --accent2:#4a6adf; --orange:#f5a623; --radius:8px; }
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:40px;width:100%;max-width:420px}
h1{font-size:20px;font-weight:600;margin-bottom:4px}
.subtitle{color:var(--text2);font-size:14px;margin-bottom:28px}
.badge{display:inline-block;font-size:11px;font-weight:600;padding:2px 10px;border-radius:10px;background:rgba(245,166,35,0.15);color:var(--orange);margin-bottom:16px}
label{display:block;margin-bottom:16px;font-size:13px;color:var(--text2);font-weight:500}
input{display:block;width:100%;margin-top:6px;padding:10px 14px;background:#232734;color:var(--text);border:1px solid var(--border);border-radius:var(--radius);font-size:14px;font-family:inherit;transition:border-color .15s}
input:focus{outline:none;border-color:var(--accent)}
button{display:block;width:100%;padding:12px;background:var(--accent);color:#fff;border:none;border-radius:var(--radius);font-size:15px;font-weight:600;cursor:pointer;transition:background .15s;margin-top:8px}
button:hover{background:var(--accent2)}
.footer{margin-top:20px;text-align:center;font-size:12px;color:var(--text2)}
.footer code{font-family:'SF Mono',Consolas,monospace;font-size:11px;background:#232734;padding:2px 6px;border-radius:4px}
</style></head>
<body>
<div class="card">
  <span class="badge">Demo Mode</span>
  <h1>Commands Gateway</h1>
  <p class="subtitle">Enter any identity to continue</p>
  <form method="post" action="/oauth/authorize">
    ` + hidden + `
    <label>Email<input name="demo_email" type="email" placeholder="alice@example.com" required autofocus/></label>
    <label>Display Name<input name="demo_name" type="text" placeholder="Alice"/></label>
    <button type="submit">Sign In</button>
  </form>
  <div class="footer">Non-production &middot; <code>AUTH_MODE=demo</code></div>
</div>
</body></html>`
}

func renderIDTokenForm(req authorizeRequest, mode string) string {
	hidden := authorizeHiddenInputs(req)
	modeLabel := html.EscapeString(strings.ToUpper(mode))
	return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><title>Sign In — Commands Gateway</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<style>
:root { --bg:#0f1117; --surface:#1a1d27; --border:#2e3345; --text:#e1e4ed; --text2:#8b91a5; --accent:#6c8cff; --accent2:#4a6adf; --radius:8px; }
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:40px;width:100%;max-width:520px}
h1{font-size:20px;font-weight:600;margin-bottom:4px}
.subtitle{color:var(--text2);font-size:14px;margin-bottom:28px}
.badge{display:inline-block;font-size:11px;font-weight:600;padding:2px 10px;border-radius:10px;background:rgba(108,140,255,0.15);color:var(--accent);margin-bottom:16px}
label{display:block;margin-bottom:16px;font-size:13px;color:var(--text2);font-weight:500}
textarea{display:block;width:100%;margin-top:6px;padding:10px 14px;background:#232734;color:var(--text);border:1px solid var(--border);border-radius:var(--radius);font-size:13px;font-family:'SF Mono',Consolas,monospace;resize:vertical;transition:border-color .15s}
textarea:focus{outline:none;border-color:var(--accent)}
button{display:block;width:100%;padding:12px;background:var(--accent);color:#fff;border:none;border-radius:var(--radius);font-size:15px;font-weight:600;cursor:pointer;transition:background .15s;margin-top:8px}
button:hover{background:var(--accent2)}
.footer{margin-top:20px;text-align:center;font-size:12px;color:var(--text2)}
</style></head>
<body>
<div class="card">
  <span class="badge">` + modeLabel + `</span>
  <h1>Commands Gateway</h1>
  <p class="subtitle">Paste a valid ID token to continue</p>
  <form method="post" action="/oauth/authorize">
    ` + hidden + `
    <label>ID Token<textarea name="id_token" rows="6" required autofocus></textarea></label>
    <button type="submit">Sign In</button>
  </form>
  <div class="footer">` + modeLabel + ` authentication</div>
</div>
</body></html>`
}

func renderFirebaseLogin(req authorizeRequest, apiKey, projectID string) string {
	hidden := authorizeHiddenInputs(req)
	escapedAPIKey := html.EscapeString(apiKey)
	escapedProjectID := html.EscapeString(projectID)
	return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><title>Sign In — Commands Gateway</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<style>
:root { --bg:#0f1117; --surface:#1a1d27; --border:#2e3345; --text:#e1e4ed; --text2:#8b91a5; --accent:#6c8cff; --accent2:#4a6adf; --green:#22c55e; --red:#ef4444; --radius:8px; }
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:40px;width:100%;max-width:460px;text-align:center}
h1{font-size:22px;font-weight:600;margin-bottom:4px}
.subtitle{color:var(--text2);font-size:14px;margin-bottom:32px}
.auth-btn{display:flex;align-items:center;justify-content:center;gap:12px;width:100%;padding:14px;background:#232734;border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:15px;font-weight:600;cursor:pointer;transition:all .15s;margin-bottom:12px}
.auth-btn:hover{border-color:var(--text2);background:#2a2f3e}
.auth-btn.google:hover{border-color:#4285f4;box-shadow:0 4px 16px rgba(66,133,244,0.2)}
.auth-btn.github:hover{border-color:#f0f0f0;box-shadow:0 4px 16px rgba(255,255,255,0.08)}
.auth-icon{width:20px;height:20px;flex-shrink:0}
.status{margin-top:20px;padding:12px 16px;border-radius:var(--radius);font-size:13px;display:none}
.status.info{display:block;background:rgba(108,140,255,0.1);border:1px solid rgba(108,140,255,0.3);color:var(--accent)}
.status.ok{display:block;background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);color:var(--green)}
.status.err{display:block;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:var(--red)}
.footer{margin-top:24px;font-size:12px;color:var(--text2)}
</style>
<script src="https://www.gstatic.com/firebasejs/9.22.2/firebase-app-compat.js"></script>
<script src="https://www.gstatic.com/firebasejs/9.22.2/firebase-auth-compat.js"></script>
</head>
<body>
<div class="card">
  <h1>Commands Gateway</h1>
  <p class="subtitle">Sign in to connect your agent</p>
  <button class="auth-btn google" onclick="signIn('google')">
    <svg class="auth-icon" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>
    Continue with Google
  </button>
  <button class="auth-btn github" onclick="signIn('github')">
    <svg class="auth-icon" viewBox="0 0 24 24" fill="#f0f0f0"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>
    Continue with GitHub
  </button>
  <div class="status" id="status"></div>
  <div class="footer">Secured by Firebase Authentication</div>
</div>
<form id="auth-form" method="post" action="/oauth/authorize" style="display:none">
  ` + hidden + `
  <input type="hidden" name="id_token" id="id-token-field"/>
</form>
<script>
firebase.initializeApp({
  apiKey: "` + escapedAPIKey + `",
  authDomain: "` + escapedProjectID + `.firebaseapp.com",
  projectId: "` + escapedProjectID + `"
});
var auth = firebase.auth();
function setStatus(cls, msg) {
  var el = document.getElementById('status');
  el.className = 'status ' + cls;
  el.textContent = msg;
}
function signIn(method) {
  var provider = method === 'github'
    ? new firebase.auth.GithubAuthProvider()
    : new firebase.auth.GoogleAuthProvider();
  if (method === 'google') { provider.addScope('email'); provider.addScope('profile'); }
  if (method === 'github') { provider.addScope('user:email'); }
  setStatus('info', 'Opening sign-in popup...');
  auth.signInWithPopup(provider).then(function(result) {
    setStatus('ok', 'Authenticated! Completing authorization...');
    return result.user.getIdToken();
  }).then(function(idToken) {
    document.getElementById('id-token-field').value = idToken;
    document.getElementById('auth-form').submit();
  }).catch(function(err) {
    var msg = err.message;
    if (err.code === 'auth/popup-closed-by-user') msg = 'Sign-in popup was closed. Please try again.';
    if (err.code === 'auth/popup-blocked') msg = 'Popup was blocked. Please allow popups and try again.';
    if (err.code === 'auth/account-exists-with-different-credential') msg = 'An account with this email exists using a different sign-in method.';
    setStatus('err', msg);
  });
}
</script>
</body></html>`
}

func authorizeHiddenInputs(req authorizeRequest) string {
	fields := map[string]string{
		"response_type":         req.ResponseType,
		"client_id":             req.ClientID,
		"redirect_uri":          req.RedirectURI,
		"scope":                 req.Scope,
		"state":                 req.State,
		"code_challenge":        req.CodeChallenge,
		"code_challenge_method": req.CodeChallengeMethod,
		"response_mode":         req.ResponseMode,
	}

	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	builder := strings.Builder{}
	for _, key := range keys {
		builder.WriteString(`<input type="hidden" name="`)
		builder.WriteString(html.EscapeString(key))
		builder.WriteString(`" value="`)
		builder.WriteString(html.EscapeString(fields[key]))
		builder.WriteString(`"/>`)
	}
	return builder.String()
}
