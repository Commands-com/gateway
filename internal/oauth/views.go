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
