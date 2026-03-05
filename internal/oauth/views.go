package oauth

import (
	"html"
	"sort"
	"strings"
)

func renderDemoLogin(req authorizeRequest) string {
	hidden := authorizeHiddenInputs(req)
	return `<html><head><title>Demo Sign In</title><meta name="viewport" content="width=device-width, initial-scale=1"/></head><body style="font-family: sans-serif; max-width: 600px; margin: 2rem auto;">
<h2>Demo Sign In (Non-Production)</h2>
<p>This gateway is running in <code>AUTH_MODE=demo</code>. Use test identity values to continue OAuth.</p>
<form method="post" action="/oauth/authorize" style="display: grid; gap: 0.75rem;">
` + hidden + `
<label>Email <input name="demo_email" type="email" placeholder="alice@example.com" /></label>
<label>Display Name <input name="demo_name" type="text" placeholder="Alice" /></label>
<label>UID (optional) <input name="demo_uid" type="text" placeholder="demo-alice" /></label>
<button type="submit">Continue</button>
</form>
</body></html>`
}

func renderIDTokenForm(req authorizeRequest, mode string) string {
	hidden := authorizeHiddenInputs(req)
	return `<html><head><title>` + html.EscapeString(strings.ToUpper(mode)) + ` Sign In</title><meta name="viewport" content="width=device-width, initial-scale=1"/></head><body style="font-family: sans-serif; max-width: 720px; margin: 2rem auto;">
<h2>` + html.EscapeString(strings.ToUpper(mode)) + ` Sign In</h2>
<p>Paste a valid ID token and continue OAuth.</p>
<form method="post" action="/oauth/authorize" style="display: grid; gap: 0.75rem;">
` + hidden + `
<label>ID Token <textarea name="id_token" rows="8" style="width: 100%;" required></textarea></label>
<button type="submit">Continue</button>
</form>
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
