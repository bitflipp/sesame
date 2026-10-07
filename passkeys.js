// Passkey (WebAuthn) glue for the sign-in portal. Buttons that need script are
// rendered hidden and revealed here, so pages stay usable without JavaScript.
(function () {
  'use strict';

  var supported = typeof window.PublicKeyCredential === 'function' &&
    typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function' &&
    typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function';

  // post sends a same-origin request and resolves with the JSON body, turning
  // any non-2xx or {"ok":false} reply into a rejection.
  function post(url, body) {
    return fetch(url, {
      method: 'POST',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      body: body === undefined ? null : JSON.stringify(body),
      credentials: 'same-origin'
    }).then(function (res) {
      return res.json().catch(function () { return { ok: false, error: 'bad_response' }; })
        .then(function (data) {
          if (!res.ok || data.ok === false) {
            throw new Error(data.error || ('http_' + res.status));
          }
          return data;
        });
    });
  }

  function showError(el, err) {
    if (!el) { return; }
    el.hidden = false;
    el.textContent = el.dataset.message || 'Passkey request failed.';
    if (window.console) { console.error(err); }
  }

  function clearError(el) {
    if (el) { el.hidden = true; }
  }

  function register() {
    var form = document.getElementById('passkey-add');
    if (!form) { return; }
    var errEl = document.getElementById('passkey-error');
    form.addEventListener('submit', function (event) {
      event.preventDefault();
      clearError(errEl);
      var nameEl = document.getElementById('passkey-name');
      var name = nameEl ? nameEl.value.trim() : '';
      post('/passkeys/register/begin')
        .then(function (options) {
          var publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey);
          return navigator.credentials.create({ publicKey: publicKey });
        })
        .then(function (credential) {
          return post('/passkeys/register/finish?name=' + encodeURIComponent(name), credential.toJSON());
        })
        .then(function (data) {
          location.assign(data.redirect || '/');
        })
        .catch(function (err) { showError(errEl, err); });
    });
  }

  function signIn() {
    var button = document.getElementById('passkey-login');
    if (!button) { return; }
    var errEl = document.getElementById('passkey-error');
    button.addEventListener('click', function () {
      clearError(errEl);
      var rd = button.dataset.rd || '';
      post('/passkeys/login/begin')
        .then(function (options) {
          var publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey);
          return navigator.credentials.get({ publicKey: publicKey });
        })
        .then(function (credential) {
          return post('/passkeys/login/finish?rd=' + encodeURIComponent(rd), credential.toJSON());
        })
        .then(function (data) {
          location.assign(data.redirect || '/');
        })
        .catch(function (err) { showError(errEl, err); });
    });
  }

  if (!supported) { return; }
  document.querySelectorAll('[data-passkey]').forEach(function (el) { el.hidden = false; });
  register();
  signIn();
})();
