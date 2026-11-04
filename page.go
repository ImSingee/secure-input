package main

import (
	_ "embed"
	"html/template"
	"time"
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
  main.wide { max-width: 880px; }
  .file-name { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 14px; font-weight: 600; margin: 0 0 2px; word-break: break-all; }
  #message { margin-bottom: 12px; }
  .countdown { font-size: 13px; font-weight: 600; color: #44403c; margin: 0 0 12px; font-variant-numeric: tabular-nums; }
  .countdown.warn { color: #c2410c; }
  .countdown.gone { color: #78716c; font-weight: 400; }
  .preview { margin: 0 0 16px; }
  .preview pre {
    margin: 0; padding: 12px; max-height: 65vh; overflow: auto;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; line-height: 1.5;
    white-space: pre-wrap; word-break: break-word;
    background: #fafaf9; border: 1px solid #e7e5e4; border-radius: 8px;
  }
  .preview img { display: block; max-width: 100%; max-height: 70vh; margin: 0 auto; border-radius: 8px; }
  .preview .empty { font-size: 12px; color: #78716c; margin: 0; }
  button:disabled { opacity: 0.5; cursor: default; }
</style>
</head>
<body><main{{if .File}} class="wide"{{end}}>
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
{{- else if .File }}
<h1>File shared by an AI agent</h1>
<div class="card">
  <p class="reason" id="message" hidden></p>
  <p class="file-name" id="file-name">Loading&hellip;</p>
  <p class="note" id="file-detail">{{.FileSize}} bytes</p>
  <p class="countdown" id="countdown" role="timer" aria-live="off"></p>
  {{if .FileEncrypted}}<p class="note">End-to-end encryption is enabled. This browser decrypts the file with the key in the link;
  the server stores only ciphertext. You must still trust the site serving this page.</p>
  {{else}}<p class="note summary warn">Encryption is disabled for this file. The server can read its name and contents.</p>{{end}}
  <div class="preview" id="preview" hidden></div>
  <div class="actions">
    <button type="button" class="decline" id="delete">Delete from server</button>
    <button type="button" class="ghost" id="copy" hidden>Copy text</button>
    <button type="button" class="primary" id="download" disabled>Download</button>
  </div>
  <p class="error" id="error" hidden></p>
</div>
<script>
{{encryptionScript}}
(function () {
  var fileID = {{.ID}};
  var encrypted = {{.FileEncrypted}};
  var remaining = {{.RemainingSeconds}};
  var loadedAt = performance.now();
  var apiURL = new URL('../api/files/' + encodeURIComponent(fileID), location.href).href;
  var imageTypes = ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif', 'image/bmp'];
  var countdown = document.getElementById('countdown');
  var preview = document.getElementById('preview');
  var error = document.getElementById('error');
  var deleteButton = document.getElementById('delete');
  var copyButton = document.getElementById('copy');
  var downloadButton = document.getElementById('download');
  var file = null;
  var text = null;
  var timer;

  function showError(message) {
    error.hidden = false;
    error.textContent = message;
  }

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' bytes';
    return (bytes / 1024).toFixed(1) + ' KiB (' + bytes + ' bytes)';
  }

  // Counts from page load rather than the client clock, so clock skew does not matter.
  function tick() {
    var left = Math.max(0, Math.ceil(remaining - (performance.now() - loadedAt) / 1000));
    if (left === 0) {
      serverGone('Expired and removed from the server.');
      return;
    }
    var minutes = Math.floor(left / 60);
    var seconds = left % 60;
    countdown.className = 'countdown' + (left <= 60 ? ' warn' : '');
    countdown.textContent = 'Removed from the server automatically in ' +
      minutes + ':' + (seconds < 10 ? '0' : '') + seconds;
  }

  function serverGone(message) {
    clearInterval(timer);
    countdown.className = 'countdown gone';
    countdown.textContent = message + (file ? ' This tab keeps its copy until you close it.' : '');
    deleteButton.disabled = true;
  }

  function decodeText(bytes) {
    try {
      var decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      return decoded.indexOf('\u0000') === -1 ? decoded : null;
    } catch (err) {
      return null;
    }
  }

  function render(opened) {
    file = opened;
    var meta = file.meta;
    document.getElementById('file-name').textContent = meta.name;
    document.getElementById('file-detail').textContent = formatSize(file.content.length) + ' \u00b7 ' + meta.type;
    document.title = meta.name + ' \u2013 shared file';
    if (meta.message) {
      var message = document.getElementById('message');
      message.textContent = meta.message;
      message.hidden = false;
    }
    var baseType = meta.type.split(';')[0].trim().toLowerCase();
    preview.hidden = false;
    if (file.content.length === 0) {
      var empty = document.createElement('p');
      empty.className = 'empty';
      empty.textContent = 'This file is empty.';
      preview.appendChild(empty);
    } else if (imageTypes.indexOf(baseType) !== -1) {
      var img = document.createElement('img');
      img.alt = meta.name;
      img.src = URL.createObjectURL(new Blob([file.content], { type: baseType }));
      img.onerror = function () {
        preview.textContent = '';
        var failed = document.createElement('p');
        failed.className = 'empty';
        failed.textContent = 'This image cannot be displayed. Download it to open it.';
        preview.appendChild(failed);
      };
      preview.appendChild(img);
    } else if ((text = decodeText(file.content)) !== null) {
      var pre = document.createElement('pre');
      pre.textContent = text;
      preview.appendChild(pre);
      copyButton.hidden = false;
    } else {
      var none = document.createElement('p');
      none.className = 'empty';
      none.textContent = 'No preview for this file type. Download it to open it.';
      preview.appendChild(none);
    }
    downloadButton.disabled = false;
  }

  timer = setInterval(tick, 1000);
  tick();

  (async function () {
    var key = checkFileShare(encrypted, location.hash);
    var res = await fetch(apiURL, { cache: 'no-store' });
    if (res.status === 410) {
      document.getElementById('file-name').textContent = 'File unavailable';
      serverGone('This file has expired or was deleted from the server.');
      return;
    }
    if (!res.ok) throw new Error('The server returned ' + res.status + '.');
    render(await openSharedFile(await res.json(), key));
  })().catch(function (err) {
    document.getElementById('file-name').textContent = 'File could not be opened';
    showError(err.message);
  });

  downloadButton.addEventListener('click', function () {
    if (!file) return;
    // octet-stream forces a download instead of rendering the file in this origin.
    var url = URL.createObjectURL(new Blob([file.content], { type: 'application/octet-stream' }));
    var link = document.createElement('a');
    link.href = url;
    link.download = file.meta.name;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
  });

  copyButton.addEventListener('click', async function () {
    try {
      await navigator.clipboard.writeText(text);
      copyButton.textContent = 'Copied';
      setTimeout(function () { copyButton.textContent = 'Copy text'; }, 1500);
    } catch (err) {
      showError('Could not copy to the clipboard. Select the text and copy it manually.');
    }
  });

  deleteButton.addEventListener('click', async function () {
    if (deleteButton.disabled) return;
    if (!confirm('Delete this file from the server now? The link will stop working.')) return;
    deleteButton.disabled = true;
    error.hidden = true;
    try {
      var res = await fetch(apiURL, { method: 'DELETE' });
      if (res.status !== 204 && res.status !== 410) throw new Error('The server returned ' + res.status + '.');
      serverGone('Deleted from the server.');
    } catch (err) {
      showError('Could not delete the file. ' + err.message);
      deleteButton.disabled = false;
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
{{- if .Footer }}
<footer>secure-input &middot; {{.Footer}}</footer>
{{- end }}
</main></body>
</html>`))

type pageData struct {
	Title            string
	File             bool
	FileEncrypted    bool
	FileSize         int
	RemainingSeconds int
	Footer           string
	ID               string
	Encryption       *EncryptionConfig
	Form             bool
	Reason           string
	Variables        []VariableSpec
	Message          string
	Muted            string
}

func renderFormPage(r *Request) pageData {
	return pageData{
		Title:      "Environment variables requested",
		Form:       true,
		ID:         r.ID,
		Encryption: r.Encryption,
		Reason:     r.Reason,
		Variables:  r.Variables,
		Footer:     requestFooter,
	}
}

const (
	requestFooter = "this link is single-use and expires 30 minutes after creation"
	fileFooter    = "shared files live only in server memory, for at most 30 minutes"
)

func renderMessagePage(title, message, muted, footer string) pageData {
	return pageData{Title: title, Message: message, Muted: muted, Footer: footer}
}

func renderFilePage(f *SharedFile) pageData {
	return pageData{
		Title:            "Shared file",
		File:             true,
		ID:               f.ID,
		FileEncrypted:    f.Upload.Encrypted != nil,
		FileSize:         f.ContentSize,
		RemainingSeconds: max(0, int(time.Until(f.ExpiresAt).Seconds())),
		Footer:           fileFooter,
	}
}
