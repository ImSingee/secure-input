package main

import (
	_ "embed"
	"html/template"
)

//go:embed web/crypto.js
var encryptionJS string

var pageTemplate = template.Must(template.New("page").Funcs(template.FuncMap{
	"encryptionScript": func() template.JS { return template.JS(encryptionJS) },
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{.Title}}</title>
<style>
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px 16px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #f5f5f4; color: #1c1917;
    display: flex; justify-content: center;
  }
  main { width: 100%; max-width: 560px; }
  h1 { font-size: 18px; margin: 0 0 4px; }
  .card {
    background: #fff; border: 1px solid #e7e5e4; border-radius: 12px;
    padding: 20px; margin-top: 16px;
  }
  .reason { font-size: 15px; font-weight: 600; margin: 0 0 4px; white-space: pre-wrap; word-break: break-word; }
  .note { font-size: 12px; color: #78716c; margin: 0 0 16px; line-height: 1.5; }
  .field { margin-bottom: 16px; }
  .field label.key {
    display: block; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 13px; font-weight: 600; margin-bottom: 2px;
  }
  .field .desc { font-size: 12px; color: #78716c; margin: 0 0 6px; white-space: pre-wrap; word-break: break-word; }
  .input-row { display: flex; gap: 8px; }
  .input-row input[type=text], .input-row input[type=password] {
    flex: 1; padding: 8px 10px; font-size: 13px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    border: 1px solid #d6d3d1; border-radius: 8px; min-width: 0;
  }
  .input-row input:focus { outline: 2px solid #f97316; outline-offset: -1px; border-color: transparent; }
  button.ghost {
    padding: 8px 10px; font-size: 12px; background: #fff;
    border: 1px solid #d6d3d1; border-radius: 8px; cursor: pointer; color: #44403c;
  }
  .private-row { display: flex; align-items: center; gap: 6px; margin-top: 6px; font-size: 12px; color: #44403c; }
  .summary { font-size: 12px; color: #78716c; margin: 4px 0 12px; }
  .summary.warn { color: #c2410c; }
  .actions { display: flex; gap: 8px; justify-content: flex-end; }
  button.primary {
    padding: 9px 16px; font-size: 13px; font-weight: 600; color: #fff;
    background: #ea580c; border: none; border-radius: 8px; cursor: pointer;
  }
  button.primary:disabled { opacity: 0.5; cursor: default; }
  button.decline {
    padding: 9px 16px; font-size: 13px; background: #fff; color: #78716c;
    border: 1px solid #d6d3d1; border-radius: 8px; cursor: pointer;
  }
  .done { text-align: center; padding: 32px 8px; }
  .done p { font-size: 14px; margin: 8px 0; }
  .done .muted { color: #78716c; font-size: 12px; }
  .error { color: #b91c1c; font-size: 12px; margin-top: 8px; }
  footer { font-size: 11px; color: #a8a29e; text-align: center; margin-top: 16px; }
</style>
</head>
<body><main>
{{- if .Form }}
<h1>Environment variables requested</h1>
<div class="card">
  <p class="reason">{{.Reason}}</p>
  <p class="note">An AI agent asked for these values. Everything you enter is saved to a file on the
  agent&rsquo;s machine. Uncheck &ldquo;Keep private&rdquo; only for non-sensitive values &mdash; those
  are sent back to the AI in plaintext.</p>
  {{if .Encryption}}<p class="note">End-to-end encryption is enabled. Values are encrypted in this browser before upload.
  You must still trust the site serving this page and the CLI receiving them.</p>
  {{else}}<p class="note summary warn">Encryption is disabled for this request. The server can read all submitted values.</p>{{end}}
  <form id="env-form">
    {{- range $i, $v := .Variables }}
    <div class="field">
      <label class="key" for="v{{$i}}">{{$v.Key}}</label>
      {{- if $v.Description }}
      <p class="desc">{{$v.Description}}</p>
      {{- end }}
      <div class="input-row">
        <input type="password" id="v{{$i}}" data-key="{{$v.Key}}"
          autocomplete="new-password" autocapitalize="none" autocorrect="off" spellcheck="false">
        <button type="button" class="ghost" data-toggle="v{{$i}}">Show</button>
      </div>
      <div class="private-row">
        <input type="checkbox" id="p{{$i}}" data-private="{{$v.Key}}"{{if $v.Private}} checked{{end}}>
        <label for="p{{$i}}">Keep private &mdash; mask the value from the AI</label>
      </div>
    </div>
    {{- end }}
    <p class="summary" id="summary"></p>
    <div class="actions">
      <button type="button" class="decline" id="decline">Decline</button>
      <button type="submit" class="primary" id="submit">Submit</button>
    </div>
    <p class="error" id="error" hidden></p>
  </form>
</div>
<script>
{{encryptionScript}}
(function () {
  var encryption = {{.Encryption}};
  var requestID = {{.ID}};
  var encryptionReady;
  var busy = false;
  var finished = false;
  var ready = false;
  var inputs = document.querySelectorAll('input[data-key]');
  var summary = document.getElementById('summary');
  var error = document.getElementById('error');

  // Check the CLI-pinned key and browser capability before accepting input.
  encryptionReady = (async function () {
    checkEncryption(encryption, location.hash);
    if (encryption) {
      var recipient = await crypto.subtle.importKey('raw', decodePublicKey(encryption.publicKey), 'X25519', false, []);
      var probe = await crypto.subtle.generateKey('X25519', false, ['deriveBits']);
      await crypto.subtle.deriveBits({ name: 'X25519', public: recipient }, probe.privateKey, 256);
    }
  })();
  inputs.forEach(function (input) { input.disabled = true; });
  document.getElementById('submit').disabled = true;
  encryptionReady.then(function () {
    inputs.forEach(function (input) { input.disabled = false; });
    ready = true;
    if (!busy && !finished) document.getElementById('submit').disabled = false;
  }).catch(function () {
    error.hidden = false;
    error.textContent = 'Encryption could not be initialized. Check the original CLI link and use HTTPS (or localhost) with a browser supporting X25519. No values have been sent.';
  });

  function updateSummary() {
    var shared = 0;
    document.querySelectorAll('input[data-private]').forEach(function (box) {
      if (!box.checked) shared++;
    });
    var total = inputs.length;
    summary.className = 'summary' + (shared > 0 ? ' warn' : '');
    summary.textContent = shared === 0
      ? total + ' variable(s) will be saved privately. Nothing is sent to the AI in plaintext.'
      : total + ' variable(s) will be saved. ' + shared + ' value(s) will be sent to the AI in plaintext.';
  }

  document.querySelectorAll('button[data-toggle]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var input = document.getElementById(btn.getAttribute('data-toggle'));
      var showing = input.type === 'text';
      input.type = showing ? 'password' : 'text';
      btn.textContent = showing ? 'Show' : 'Hide';
    });
  });

  document.querySelectorAll('input[data-private]').forEach(function (box) {
    box.addEventListener('change', updateSummary);
  });
  updateSummary();

  function setBusy(value) {
    busy = value;
    document.getElementById('submit').disabled = value || !ready;
    document.getElementById('decline').disabled = value;
  }

  function finish(ok, message) {
    finished = true;
    document.querySelector('main').innerHTML =
      '<div class="card"><div class="done"><p>' +
      (ok ? 'Saved.' : 'Something went wrong.') + '</p><p class="muted">' +
      message + '</p></div></div>';
  }

  document.getElementById('env-form').addEventListener('submit', async function (event) {
    event.preventDefault();
    var submit = document.getElementById('submit');
    if (submit.disabled || busy || finished) return;
    setBusy(true);
    error.hidden = true;
    try {
      await encryptionReady;
      var entries = [];
      inputs.forEach(function (input) {
        if (new TextEncoder().encode(input.value).length > 64 * 1024) throw new Error('A value exceeds 65536 bytes.');
        entries.push({
          key: input.getAttribute('data-key'),
          value: input.value,
          private: document.querySelector('input[data-private="' + input.getAttribute('data-key') + '"]').checked
        });
      });
      var payload = encryption
        ? { encrypted: await encryptSubmission(entries, encryption, requestID) }
        : { entries: entries };
      var res = await fetch(location.pathname + '/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!res.ok) throw new Error('Request expired, already submitted, or rejected.');
      inputs.forEach(function (input) { input.value = ''; });
      finish(true, 'The agent has been notified. You can close this tab.');
    } catch (err) {
      error.hidden = false;
      error.textContent = 'Submission failed. No plaintext fallback was attempted. Your values are still here; try again. ' + err.message;
      setBusy(false);
    }
  });

  document.getElementById('decline').addEventListener('click', async function () {
    if (busy || finished) return;
    if (!confirm('Decline this request? The agent will be notified and get no values.')) return;
    setBusy(true);
    error.hidden = true;
    try {
      var res = await fetch(location.pathname + '/decline', { method: 'POST' });
      if (!res.ok) throw new Error('The request may have expired or already been answered.');
      finish(true, 'Request declined. You can close this tab.');
    } catch (err) {
      error.hidden = false;
      error.textContent = 'Could not decline the request. ' + err.message;
      setBusy(false);
    }
  });
})();
</script>
{{- else }}
<div class="card"><div class="done">
  <p>{{.Message}}</p>
  {{- if .Muted }}<p class="muted">{{.Muted}}</p>{{- end }}
</div></div>
{{- end }}
<footer>secure-input &middot; this link is single-use and expires 30 minutes after creation</footer>
</main></body>
</html>`))

type pageData struct {
	Title      string
	ID         string
	Encryption *EncryptionConfig
	Form       bool
	Reason     string
	Variables  []VariableSpec
	Message    string
	Muted      string
}

func renderFormPage(r *Request) pageData {
	return pageData{
		Title:      "Environment variables requested",
		Form:       true,
		ID:         r.ID,
		Encryption: r.Encryption,
		Reason:     r.Reason,
		Variables:  r.Variables,
	}
}

func renderMessagePage(title, message, muted string) pageData {
	return pageData{Title: title, Message: message, Muted: muted}
}
