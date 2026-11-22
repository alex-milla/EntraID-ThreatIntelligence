/**
 * webauthn.js — Cliente de passkeys (v0.4.28.17).
 * Solo se carga en las pantallas de login/seguridad cuando WebAuthn está
 * habilitado. No cambia el formulario de contraseña.
 */
(function () {
    'use strict';

    function b64uToBuffer(value) {
        var s = String(value).replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4) { s += '='; }
        var bin = atob(s);
        var out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
        return out.buffer;
    }

    function bufferToB64u(buffer) {
        var bytes = new Uint8Array(buffer);
        var s = '';
        for (var i = 0; i < bytes.length; i++) { s += String.fromCharCode(bytes[i]); }
        return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function serializeAssertion(credential) {
        var response = credential.response;
        return {
            id: credential.id,
            rawId: bufferToB64u(credential.rawId),
            type: credential.type,
            response: {
                authenticatorData: bufferToB64u(response.authenticatorData),
                clientDataJSON: bufferToB64u(response.clientDataJSON),
                signature: bufferToB64u(response.signature),
                userHandle: response.userHandle ? bufferToB64u(response.userHandle) : null
            },
            clientExtensionResults: credential.getClientExtensionResults
                ? credential.getClientExtensionResults() : {}
        };
    }

    function serializeAttestation(credential) {
        var response = credential.response;
        return {
            id: credential.id,
            rawId: bufferToB64u(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: bufferToB64u(response.attestationObject),
                clientDataJSON: bufferToB64u(response.clientDataJSON),
                transports: response.getTransports ? response.getTransports() : []
            },
            clientExtensionResults: credential.getClientExtensionResults
                ? credential.getClientExtensionResults() : {}
        };
    }

    window.EitiWebAuthn = {
        available: function () {
            return !!(window.PublicKeyCredential && navigator.credentials
                && navigator.credentials.create && navigator.credentials.get
                && window.isSecureContext);
        },

        post: function (url, payload) {
            var token = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            return fetch(url, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': token,
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify(payload || {})
            }).then(function (r) { return r.json(); });
        },

        register: function (urlOptions, urlVerify) {
            if (!this.available()) {
                return Promise.reject(new Error('Este navegador no admite passkeys'));
            }
            return fetch(urlOptions, { credentials: 'same-origin' })
                .then(function (r) { return r.json(); })
                .then(function (options) {
                    if (!options || !options.success) {
                        throw new Error(options && options.error ? options.error : 'No se pudieron obtener las opciones');
                    }
                    var pub = options.options;
                    pub.challenge = b64uToBuffer(pub.challenge);
                    pub.user.id = b64uToBuffer(pub.user.id);
                    if (pub.excludeCredentials) {
                        pub.excludeCredentials.forEach(function (c) { c.id = b64uToBuffer(c.id); });
                    }
                    return navigator.credentials.create({ publicKey: pub });
                })
                .then(function (credential) {
                    if (!credential) { throw new Error('No se creó la passkey'); }
                    return this.post(urlVerify, serializeAttestation(credential));
                }.bind(this));
        },

        authenticate: function (urlOptions, urlVerify, username) {
            if (!this.available()) {
                return Promise.reject(new Error('Este navegador no admite passkeys'));
            }
            var qs = username ? '?username=' + encodeURIComponent(username) : '';
            return fetch(urlOptions + qs, { credentials: 'same-origin' })
                .then(function (r) { return r.json(); })
                .then(function (options) {
                    if (!options || !options.success) {
                        throw new Error(options && options.error ? options.error : 'No se pudieron obtener las opciones');
                    }
                    var pub = options.options;
                    pub.challenge = b64uToBuffer(pub.challenge);
                    if (pub.allowCredentials) {
                        pub.allowCredentials.forEach(function (c) { c.id = b64uToBuffer(c.id); });
                    }
                    return navigator.credentials.get({ publicKey: pub });
                })
                .then(function (credential) {
                    if (!credential) { throw new Error('No se obtuvo la passkey'); }
                    return this.post(urlVerify, serializeAssertion(credential));
                }.bind(this));
        }
    };
})();
