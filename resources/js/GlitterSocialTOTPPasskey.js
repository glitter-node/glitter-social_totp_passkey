(function (window) {
    'use strict';

    var copyButtonId = 'glitter-social_totp_passkey-registration-totp-copy';
    var manualKeyId = 'glitter-social_totp_passkey-registration-totp-manual-key';
    var copySuccessId = 'glitter-social_totp_passkey-registration-totp-copy-success';
    var copyFailedId = 'glitter-social_totp_passkey-registration-totp-copy-failed';

    function copyManualKey(input) {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(input.value);
        }

        input.focus();
        input.select();
        if (!document.execCommand('copy')) {
            return Promise.reject(new Error('clipboard_unavailable'));
        }

        return Promise.resolve();
    }

    function handleCopy(event) {
        var target = event.target;
        var button = target && target.closest ? target.closest('#' + copyButtonId) : null;
        if (!button) {
            return;
        }

        event.preventDefault();

        var input = document.getElementById(manualKeyId);
        if (!input || typeof input.value !== 'string' || input.value === '') {
            return;
        }

        var originalText = button.textContent;
        copyManualKey(input).then(function () {
            var success = document.getElementById(copySuccessId);
            button.textContent = success ? success.textContent : originalText;
            window.setTimeout(function () {
                button.textContent = originalText;
            }, 1800);
        }).catch(function () {
            var failed = document.getElementById(copyFailedId);
            button.textContent = failed ? failed.textContent : originalText;
        });
    }

    function bindCopyHandler() {
        if (typeof document === 'undefined' || window.__glitterSocialTOTPPasskeyCopyBound) {
            return;
        }

        document.addEventListener('click', handleCopy);
        window.__glitterSocialTOTPPasskeyCopyBound = true;
    }

    bindCopyHandler();

    var identifier = 'glitter-social_totp_passkey';
    var apiPrefix = '/api/plugins/' + identifier;
    var passkeyTotpSubmitting = false;
    var passkeyManagementReauthTimer = null;
    var passkeyManagementReauthTimerToken = null;
    var passkeyManagementReauthTimerGeneration = null;
    var passkeyManagementAuthBound = false;
    var passkeyManagementReauthLifetimeMs = 285000;
    var passkeyManagementReauthControlKey = '__glitterSocialTOTPPasskeyReauthControl';

    function failure(stage, name, status, message) {
        var safeMessage = message || ('Passkey reauthentication failed during ' + stage + (status ? ' (HTTP ' + status + ')' : '') + '.');
        var error = new Error(safeMessage);
        error.name = name || 'PasskeyError';
        error.stage = stage;
        error.status = status || 0;
        error.response = { status: error.status, data: { message: error.message } };
        return error;
    }

    function errorStatus(error) {
        if (error && error.response && Number.isFinite(error.response.status)) return error.response.status;
        if (error && Number.isFinite(error.status)) return error.status;
        return 0;
    }

    function errorName(error) {
        var name = error && typeof error.name === 'string' ? error.name : '';
        return /^[A-Za-z][A-Za-z0-9_]{0,40}$/.test(name) ? name : 'PasskeyError';
    }

    function errorCode(error) {
        var code = error && error.response && error.response.data && error.response.data.error_code;
        return typeof code === 'string' ? code : '';
    }

    function wrapFailure(stage, error) {
        if (error && error.stage === stage) return error;
        var name = errorName(error);
        var status = errorStatus(error);
        var message = name === 'NotAllowedError' && stage === 'webauthn_get'
            ? 'Passkey authentication was cancelled during webauthn_get.'
            : 'Passkey reauthentication failed during ' + stage + ' (' + name + (status ? ', HTTP ' + status : '') + ').';
        var wrapped = failure(stage, name, status, message);
        wrapped.errorCode = errorCode(error);
        if (error && error.response) wrapped.response = error.response;
        return wrapped;
    }

    function validObject(value) {
        return value !== null && typeof value === 'object' && !Array.isArray(value);
    }

    function validDate(value) {
        return typeof value === 'string' && value !== '' && Number.isFinite(Date.parse(value));
    }

    function safeRedirectPath(value) {
        if (typeof value !== 'string' || value.charAt(0) !== '/' || value.charAt(1) === '/') return '/';
        if (value.indexOf('\\') !== -1 || /[\u0000-\u0020\u007f]/.test(value)) return '/';
        return value;
    }

    async function setGlobalState(values) {
        if (!window.G7Core || typeof window.G7Core.dispatch !== 'function') {
            throw failure('state_update', 'StateDispatchUnavailable');
        }
        var dispatched = await window.G7Core.dispatch({ handler: 'setState', params: Object.assign({ target: 'global' }, values) });
        if (!dispatched || dispatched.success === false) {
            throw failure('state_update', 'StateDispatchFailed');
        }
    }

    async function clearPasskeyLoginState() {
        await setGlobalState({
            glitterPasskeyTotpPending: null,
            glitterPasskeyTotpExpiresAt: null,
            glitterPasskeyTotpSubmitting: false,
            glitterPasskeyPasswordChange: null,
            glitterPasskeyPasswordChangeSubmitting: false,
        });
    }

    function globalState() {
        var state = window.G7Core && window.G7Core.state;
        return state && typeof state.getGlobal === 'function' ? state.getGlobal() || {} : {};
    }

    function passkeyManagementReauthControl(state) {
        var control = state && state[passkeyManagementReauthControlKey];
        return validObject(control) ? control : {};
    }

    function updatePasskeyManagementState(updater) {
        var stateApi = window.G7Core && window.G7Core.state;
        if (!stateApi || typeof stateApi.update !== 'function' || typeof stateApi.getGlobal !== 'function') {
            throw failure('reauth_state_update', 'StateUpdateUnavailable');
        }

        stateApi.update(function (current) {
            return updater(validObject(current) ? current : {});
        });
    }

    function nextPasskeyManagementReauthGeneration(current) {
        var control = passkeyManagementReauthControl(current);
        var generation = control.requestGeneration;
        if (generation === undefined) generation = 0;
        if (!Number.isSafeInteger(generation) || generation < 0 || generation >= Number.MAX_SAFE_INTEGER) {
            throw failure('reauth_state_update', 'StateGenerationUnavailable');
        }
        return generation + 1;
    }

    function beginPasskeyManagementReauthentication() {
        var before = globalState();
        var generation = nextPasskeyManagementReauthGeneration(before);
        updatePasskeyManagementState(function (current) {
            var control = passkeyManagementReauthControl(current);
            if ((control.requestGeneration || 0) !== generation - 1) return current;
            return Object.assign({}, current, {
                [passkeyManagementReauthControlKey]: Object.assign({}, control, { requestGeneration: generation }),
            });
        });

        if (passkeyManagementReauthControl(globalState()).requestGeneration !== generation) {
            throw failure('reauth_state_update', 'StateGenerationChanged');
        }
        return generation;
    }

    function clearPasskeyManagementReauthentication(expectedToken, expectedGeneration) {
        var before = globalState();
        updatePasskeyManagementState(function (current) {
            var control = passkeyManagementReauthControl(current);
            if (expectedToken && current.socialTotpPasskeyReauthToken !== expectedToken) return current;
            if (expectedGeneration !== undefined && control.tokenGeneration !== expectedGeneration) return current;
            return Object.assign({}, current, {
                socialTotpPasskeyReauthToken: null,
                socialTotpPasskeyReauthExpiresAt: null,
                socialTotpPasskeyEnrollment: null,
                [passkeyManagementReauthControlKey]: Object.assign({}, control, { tokenGeneration: null }),
            });
        });

        var after = globalState();
        var beforeControl = passkeyManagementReauthControl(before);
        var afterControl = passkeyManagementReauthControl(after);
        var expectedStillCurrent = expectedToken
            ? after.socialTotpPasskeyReauthToken === expectedToken
                && (expectedGeneration === undefined || afterControl.tokenGeneration === expectedGeneration)
            : after.socialTotpPasskeyReauthToken !== null && after.socialTotpPasskeyReauthToken !== undefined;

        if (!expectedStillCurrent) {
            var timerMatches = passkeyManagementReauthTimer !== null
                && (!expectedToken || passkeyManagementReauthTimerToken === expectedToken)
                && (expectedGeneration === undefined || passkeyManagementReauthTimerGeneration === expectedGeneration);
            if (timerMatches) {
                window.clearTimeout(passkeyManagementReauthTimer);
                passkeyManagementReauthTimer = null;
                passkeyManagementReauthTimerToken = null;
                passkeyManagementReauthTimerGeneration = null;
            }
            return true;
        }

        // A failed/no-op updater must not cancel a timer for the still-current credential.
        if (before.socialTotpPasskeyReauthToken === after.socialTotpPasskeyReauthToken
            && before.socialTotpPasskeyReauthExpiresAt === after.socialTotpPasskeyReauthExpiresAt
            && beforeControl.tokenGeneration === afterControl.tokenGeneration) {
            return false;
        }
        return false;
    }

    function invalidatePasskeyManagementReauthenticationRequests() {
        var before = globalState();
        var generation = nextPasskeyManagementReauthGeneration(before);
        updatePasskeyManagementState(function (current) {
            var control = passkeyManagementReauthControl(current);
            if ((control.requestGeneration || 0) !== generation - 1) return current;
            return Object.assign({}, current, {
                socialTotpPasskeyReauthToken: null,
                socialTotpPasskeyReauthExpiresAt: null,
                socialTotpPasskeyEnrollment: null,
                [passkeyManagementReauthControlKey]: Object.assign({}, control, {
                    requestGeneration: generation,
                    tokenGeneration: null,
                }),
            });
        });

        var after = globalState();
        if (passkeyManagementReauthControl(after).requestGeneration !== generation) return false;
        if (passkeyManagementReauthTimer !== null) window.clearTimeout(passkeyManagementReauthTimer);
        passkeyManagementReauthTimer = null;
        passkeyManagementReauthTimerToken = null;
        passkeyManagementReauthTimerGeneration = null;
        return true;
    }

    async function storePasskeyManagementReauthentication(token, requestGeneration) {
        if (typeof token !== 'string' || !/^[A-Za-z0-9]{64}$/.test(token)) {
            throw failure('reauth_token_processing', 'InvalidReauthToken');
        }
        if (!Number.isSafeInteger(requestGeneration)) return 'failed';
        var expiresAt = new Date(Date.now() + passkeyManagementReauthLifetimeMs).toISOString();
        updatePasskeyManagementState(function (current) {
            var control = passkeyManagementReauthControl(current);
            if (control.requestGeneration !== requestGeneration) return current;
            return Object.assign({}, current, {
                socialTotpPasskeyReauthToken: token,
                socialTotpPasskeyReauthExpiresAt: expiresAt,
                socialTotpPasskeyEnrollment: null,
                [passkeyManagementReauthControlKey]: Object.assign({}, control, { tokenGeneration: requestGeneration }),
            });
        });

        var after = globalState();
        var afterControl = passkeyManagementReauthControl(after);
        if (afterControl.requestGeneration !== requestGeneration) return 'stale';
        if (after.socialTotpPasskeyReauthToken !== token
            || after.socialTotpPasskeyReauthExpiresAt !== expiresAt
            || afterControl.tokenGeneration !== requestGeneration) return 'failed';

        if (passkeyManagementReauthTimer !== null) window.clearTimeout(passkeyManagementReauthTimer);
        passkeyManagementReauthTimer = window.setTimeout(function () {
            try {
                clearPasskeyManagementReauthentication(token, requestGeneration);
            } catch (_) {
                // Timer failure is fail-closed at the server TTL boundary.
            }
        }, passkeyManagementReauthLifetimeMs);
        passkeyManagementReauthTimerToken = token;
        passkeyManagementReauthTimerGeneration = requestGeneration;
        return 'stored';
    }

    function requireStoredPasskeyManagementReauthentication(result) {
        if (result === 'stored') return;
        if (result === 'stale') {
            // 음수 코드는 클라이언트 내부 전용이므로 HTTP 응답 상태와 겹치지 않는다.
            throw failure('reauth_token_processing', 'StaleReauthentication', -1,
                'Passkey reauthentication response is stale.');
        }
        throw failure('reauth_token_processing', 'StateUpdateFailed', 0,
            '$t:glitter-social_totp_passkey.profile.totp_reauth_failed');
    }

    function throwDispatchedApiError(dispatched, stage, fallbackMessage) {
        var actionError = dispatched && dispatched.error;
        var original = actionError && actionError.originalError;
        if (original instanceof Error) {
            var response = original.response;
            var code = response && (response.error_code || (response.data && response.data.error_code));
            if (typeof code === 'string') original.error_code = code;
            if (response && typeof response === 'object') {
                original.response = { status: original.status, data: response };
            }
            throw original;
        }
        throw failure(stage, 'ApiCallFailed', errorStatus(actionError), fallbackMessage);
    }

    function reauthenticationMustRestart(error) {
        var code = errorCode(error);
        return errorStatus(error) === 419
            || code === 'passkey_reauthentication_required'
            || code === 'social_totp_passkey_totp_reauthentication_required';
    }

    async function clearPasskeyManagementReauthenticationAction(action) {
        var expectedToken = (action.params || {}).expectedToken;
        if (typeof expectedToken !== 'string' || !/^[A-Za-z0-9]{64}$/.test(expectedToken)) return false;
        return clearPasskeyManagementReauthentication(expectedToken);
    }

    function clearExpiredPasskeyManagementReauthentication() {
        var state = globalState();
        var token = state.socialTotpPasskeyReauthToken;
        var expiresAt = Date.parse(state.socialTotpPasskeyReauthExpiresAt || '');
        if (token && (!Number.isFinite(expiresAt) || expiresAt <= Date.now())) {
            var tokenGeneration = passkeyManagementReauthControl(state).tokenGeneration;
            try {
                clearPasskeyManagementReauthentication(token, tokenGeneration);
            } catch (_) {
                // Server-side TTL and binding remain authoritative.
            }
        }
    }

    function bindPasskeyManagementAuthState() {
        if (passkeyManagementAuthBound || !window.G7Core || !window.G7Core.AuthManager) return;
        var auth = window.G7Core.AuthManager.getInstance();
        if (!auth || typeof auth.on !== 'function') return;
        passkeyManagementAuthBound = true;
        auth.on('logout', function () {
            try { invalidatePasskeyManagementReauthenticationRequests(); } catch (_) {}
        });
        auth.on('authStateChange', function (state) {
            if (!state || state.isAuthenticated !== true) {
                try { invalidatePasskeyManagementReauthenticationRequests(); } catch (_) {}
            }
        });
        window.addEventListener('focus', clearExpiredPasskeyManagementReauthentication);
        document.addEventListener('visibilitychange', function () {
            if (document.visibilityState === 'visible') clearExpiredPasskeyManagementReauthentication();
        });
        clearExpiredPasskeyManagementReauthentication();
    }

    async function handleLoginResult(result) {
        if (!validObject(result)) throw failure('login_response', 'InvalidLoginResponse');

        if (result.password_change_required === true) {
            if (typeof result.challenge_id !== 'string' || result.challenge_id === ''
                || !['expired', 'admin_assigned'].includes(result.reason)
                || typeof result.can_postpone !== 'boolean'
                || (result.postpone_days !== null && !Number.isInteger(result.postpone_days))
                || (result.expired_at !== null && !validDate(result.expired_at))
                || !validDate(result.expires_at)
            ) {
                throw failure('password_change_response', 'InvalidPasswordChangeResponse');
            }
            await setGlobalState({
                glitterPasskeyTotpPending: null,
                glitterPasskeyTotpExpiresAt: null,
                glitterPasskeyTotpSubmitting: false,
                glitterPasskeyPasswordChangeSubmitting: false,
                glitterPasskeyPasswordChange: {
                    required: true,
                    challenge_id: result.challenge_id,
                    reason: result.reason,
                    can_postpone: result.can_postpone,
                    postpone_days: result.postpone_days,
                    expired_at: result.expired_at,
                    expires_at: result.expires_at,
                },
            });
            return result;
        }

        if (result.totp_required === true) {
            if (typeof result.pending_id !== 'string' || result.pending_id.length !== 48 || !validDate(result.expires_at)) {
                throw failure('totp_response', 'InvalidTotpResponse');
            }
            await setGlobalState({
                glitterPasskeyTotpPending: result.pending_id,
                glitterPasskeyTotpExpiresAt: result.expires_at,
                glitterPasskeyTotpSubmitting: false,
                glitterPasskeyPasswordChange: null,
                glitterPasskeyPasswordChangeSubmitting: false,
            });
            return result;
        }

        if (typeof result.token === 'string' && result.token !== ''
            && validObject(result.data)
            && typeof result.data.uuid === 'string' && result.data.uuid !== ''
        ) {
            await clearPasskeyLoginState();
            window.localStorage.setItem('auth_token', result.token);
            window.location.assign(safeRedirectPath(result.redirect_path));
            return result;
        }

        throw failure('login_response', 'InvalidLoginResponse');
    }

    function decode(value) {
        if (typeof value !== 'string' || value === '' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
            throw new Error('invalid_base64url');
        }
        var base64 = value.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) base64 += '=';
        var binary = window.atob(base64);
        var bytes = new Uint8Array(binary.length);
        for (var index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
        return bytes.buffer;
    }

    function encode(value) {
        if (!value || typeof value.byteLength !== 'number') throw new Error('invalid_binary');
        var bytes = new Uint8Array(value);
        var binary = '';
        bytes.forEach(function (byte) { binary += String.fromCharCode(byte); });
        return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }

    function creationOptions(publicKey) {
        if (!publicKey || typeof publicKey !== 'object') throw new Error('missing_public_key');
        var normalized = Object.assign({}, publicKey);
        normalized.challenge = decode(publicKey.challenge);
        normalized.user = Object.assign({}, publicKey.user, { id: decode(publicKey.user.id) });
        normalized.excludeCredentials = (publicKey.excludeCredentials || []).map(function (item) {
            return Object.assign({}, item, { id: decode(item.id) });
        });
        return normalized;
    }

    function requestOptions(publicKey) {
        if (!publicKey || typeof publicKey !== 'object') throw new Error('missing_public_key');
        var normalized = Object.assign({}, publicKey);
        normalized.challenge = decode(publicKey.challenge);
        if (publicKey.allowCredentials !== undefined && !Array.isArray(publicKey.allowCredentials)) {
            throw new Error('invalid_allow_credentials');
        }
        normalized.allowCredentials = (publicKey.allowCredentials || []).map(function (item) {
            if (!item || typeof item.id !== 'string') throw new Error('invalid_credential_id');
            return Object.assign({}, item, { id: decode(item.id) });
        });
        return normalized;
    }

    function credentialJson(credential) {
        var response = credential.response;
        var result = {
            id: credential.id,
            rawId: encode(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: encode(response.clientDataJSON),
            },
        };
        if (response.attestationObject) {
            result.response.attestationObject = encode(response.attestationObject);
            result.response.transports = typeof response.getTransports === 'function' ? response.getTransports() : [];
        } else {
            result.response.authenticatorData = encode(response.authenticatorData);
            result.response.signature = encode(response.signature);
            result.response.userHandle = response.userHandle ? encode(response.userHandle) : null;
        }
        if (typeof credential.getClientExtensionResults === 'function') {
            result.clientExtensionResults = credential.getClientExtensionResults();
        }
        return result;
    }

    async function post(context, path, body, stage) {
        var api = window.G7Core && window.G7Core.api;
        if (api && typeof api.post === 'function') {
            try {
                return await api.post(apiPrefix + path, body);
            } catch (error) {
                throw wrapFailure(stage, error);
            }
        }
        var token = window.localStorage ? window.localStorage.getItem('auth_token') : null;
        var xsrf = document.cookie.split('; ').find(function (item) { return item.indexOf('XSRF-TOKEN=') === 0; });
        var headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
        if (token) headers.Authorization = 'Bearer ' + token;
        if (xsrf) headers['X-XSRF-TOKEN'] = decodeURIComponent(xsrf.substring('XSRF-TOKEN='.length));
        try {
            var response = await window.fetch(apiPrefix + path, {
                method: 'POST', credentials: 'same-origin', headers: headers, body: JSON.stringify(body || {}),
            });
            var payload = await response.json();
            if (!response.ok) {
                var httpError = failure(stage, 'HttpError', response.status);
                httpError.response = {
                    status: response.status,
                    data: validObject(payload) ? payload : {},
                };
                throw httpError;
            }
            return payload;
        } catch (error) {
            throw wrapFailure(stage, error);
        }
    }

    async function authenticate(action, context) {
        if (!window.PublicKeyCredential || !navigator.credentials || typeof navigator.credentials.get !== 'function') throw failure('webauthn_get', 'NotSupportedError');
        var params = action.params || {};
        var purpose = params.purpose || 'login';
        var reauthGeneration = purpose === 'reauth' ? beginPasskeyManagementReauthentication() : null;
        var request = { purpose: purpose };
        if (params.pendingId) request.pending_id = params.pendingId;
        var optionsPath = purpose === 'reauth' ? '/passkey/reauthenticate/options' : '/passkey/authenticate/options';
        var verifyPath = purpose === 'reauth' ? '/passkey/reauthenticate/verify' : '/passkey/authenticate/verify';
        var options = await post(context, optionsPath, purpose === 'reauth' ? {} : request, 'options_request');
        if (!options || typeof options !== 'object' || typeof options.challenge_id !== 'string' || !options.challenge_id || !options.publicKey || typeof options.publicKey !== 'object') {
            throw failure('options_parse', 'InvalidOptions');
        }
        var publicKey;
        try {
            publicKey = requestOptions(options.publicKey);
        } catch (error) {
            throw wrapFailure('webauthn_options_conversion', error);
        }
        var credential;
        try {
            credential = await navigator.credentials.get({ publicKey: publicKey });
            if (!credential) throw new Error('empty_credential');
        } catch (error) {
            throw wrapFailure('webauthn_get', error);
        }
        var serializedCredential;
        try {
            serializedCredential = credentialJson(credential);
        } catch (error) {
            throw wrapFailure('assertion_serialization', error);
        }
        var verification = {
            purpose: purpose,
            pending_id: params.pendingId || null,
            challenge_id: options.challenge_id,
            credential: serializedCredential,
        };
        if (purpose === 'reauth') {
            delete verification.purpose;
            delete verification.pending_id;
        }
        var result = await post(context, verifyPath, verification, 'verify_request');

        if (!result || typeof result !== 'object') {
            throw failure(purpose === 'reauth' ? 'reauth_token_processing' : 'verify_request', 'InvalidVerifyResponse');
        }

        if (purpose === 'reauth') {
            try {
                requireStoredPasskeyManagementReauthentication(
                    await storePasskeyManagementReauthentication(result.reauth_token, reauthGeneration)
                );
            } catch (error) {
                throw wrapFailure('reauth_token_processing', error);
            }
            return result;
        }

        if (purpose === 'social' && result.redirect_url) {
            window.location.assign(result.redirect_url);
            return result;
        }
        if (purpose === 'social') throw failure('social_response', 'InvalidSocialResponse');

        return handleLoginResult(result);
    }

    async function reauthenticateWithPassword(action) {
        var params = action.params || {};
        var password = typeof params.password === 'string' ? params.password : '';
        if (password === '') throw failure('password_reauthentication', 'InvalidPasswordReauthentication');

        var generation = beginPasskeyManagementReauthentication();
        var dispatched = await window.G7Core.dispatch({
            handler: 'apiCall',
            auth_required: true,
            target: apiPrefix + '/totp/reauthenticate',
            params: { method: 'POST', body: { password: password } },
            onError: [{ handler: 'suppress' }],
        });
        if (!dispatched || dispatched.success !== true) {
            throwDispatchedApiError(dispatched, 'password_reauthentication',
                '$t:glitter-social_totp_passkey.profile.totp_reauth_failed');
        }
        if (!validObject(dispatched.data)) {
            throw failure('password_reauthentication', 'InvalidReauthenticationResponse', 0,
                '$t:glitter-social_totp_passkey.profile.totp_reauth_failed');
        }

        requireStoredPasskeyManagementReauthentication(
            await storePasskeyManagementReauthentication(dispatched.data.reauth_token, generation)
        );
        return dispatched.data;
    }

    async function disableTotp(action) {
        var reauthToken = (action.params || {}).reauthToken;
        var code = (action.params || {}).code;
        var dispatched = await window.G7Core.dispatch({
            handler: 'apiCall',
            auth_required: true,
            target: apiPrefix + '/totp',
            params: { method: 'DELETE', body: { reauth_token: reauthToken, code: code } },
            onError: [{ handler: 'suppress' }],
        });
        if (!dispatched || dispatched.success !== true) {
            throwDispatchedApiError(dispatched, 'totp_disable',
                '$t:glitter-social_totp_passkey.profile.totp_disable_failed');
        }
        clearPasskeyManagementReauthentication(reauthToken);
        return dispatched.data;
    }

    async function completePasskeyTotp(action, context) {
        var params = action.params || {};
        var pendingId = typeof params.pendingId === 'string' ? params.pendingId : '';
        var code = typeof params.code === 'string' ? params.code : '';
        var expiresAt = typeof params.expiresAt === 'string' ? params.expiresAt : '';

        if (passkeyTotpSubmitting) throw failure('totp_submit', 'PasskeyLoginInProgress', 409);
        if (pendingId.length !== 48 || !/^\d{6}$/.test(code)) throw failure('totp_submit', 'InvalidTotpRequest');
        if (!validDate(expiresAt) || Date.parse(expiresAt) <= Date.now()) {
            await clearPasskeyLoginState();
            throw failure('totp_submit', 'PasskeyLoginExpired', 410);
        }

        passkeyTotpSubmitting = true;
        await setGlobalState({ glitterPasskeyTotpSubmitting: true });

        try {
            var result = await post(context, '/passkey/authenticate/totp', {
                pending_id: pendingId,
                code: code,
            }, 'totp_submit');
            return await handleLoginResult(result);
        } catch (error) {
            var codeName = errorCode(error) || error.errorCode || '';
            if (codeName === 'passkey_login_expired' || codeName === 'passkey_login_stale') {
                await clearPasskeyLoginState();
            }
            throw error;
        } finally {
            passkeyTotpSubmitting = false;
            try {
                await setGlobalState({ glitterPasskeyTotpSubmitting: false });
            } catch (_) {
                // The request remains failed closed even if UI state cleanup cannot be rendered.
            }
        }
    }

    async function register(action, context) {
        if (!window.PublicKeyCredential || !navigator.credentials || typeof navigator.credentials.create !== 'function') throw new Error('passkey_unsupported');
        var params = action.params || {};
        var options;
        try {
            options = await post(context, '/passkey/register/options', { reauth_token: params.reauthToken }, 'options_request');
        } catch (error) {
            if (reauthenticationMustRestart(error)) clearPasskeyManagementReauthentication(params.reauthToken);
            throw error;
        }
        if (!options || typeof options !== 'object' || typeof options.challenge_id !== 'string' || !options.challenge_id || !options.publicKey || typeof options.publicKey !== 'object') {
            throw failure('registration_options_parse', 'InvalidOptions', 0, '$t:glitter-social_totp_passkey.profile.passkey_registration_failed');
        }
        var publicKey;
        try {
            publicKey = creationOptions(options.publicKey);
        } catch (_) {
            throw failure('registration_options_conversion', 'InvalidOptions', 0, '$t:glitter-social_totp_passkey.profile.passkey_registration_failed');
        }
        var credential;
        try {
            credential = await navigator.credentials.create({ publicKey: publicKey });
        } catch (error) {
            var name = errorName(error);
            var message = name === 'InvalidStateError'
                ? '$t:glitter-social_totp_passkey.profile.passkey_already_registered'
                : name === 'NotAllowedError'
                    ? '$t:glitter-social_totp_passkey.profile.passkey_registration_not_completed'
                    : '$t:glitter-social_totp_passkey.profile.passkey_registration_failed';
            throw failure('webauthn_create', name, 0, message);
        }
        if (!credential) {
            throw failure('webauthn_create', 'EmptyCredential', 0, '$t:glitter-social_totp_passkey.profile.passkey_registration_failed');
        }
        var result;
        try {
            result = await post(context, '/passkey/register/verify', {
                challenge_id: options.challenge_id,
                credential: credentialJson(credential),
                name: params.name || 'Passkey',
                reauth_token: params.reauthToken,
            }, 'verify_request');
        } catch (error) {
            if (reauthenticationMustRestart(error)) clearPasskeyManagementReauthentication(params.reauthToken);
            throw error;
        }
        if (window.G7Core && window.G7Core.dispatch) {
            await window.G7Core.dispatch({ handler: 'refetchDataSource', params: { dataSourceId: 'glitter_social_totp_passkey_credentials' } });
        }
        return result;
    }

    async function deletePasskey(action) {
        var params = action.params || {};
        var credentialId = String(params.credentialId || '');
        var reauthToken = typeof params.reauthToken === 'string' ? params.reauthToken : '';
        if (!/^\d+$/.test(credentialId) || credentialId === '0' || !/^[A-Za-z0-9]{64}$/.test(reauthToken)) {
            throw failure('delete_request', 'InvalidDeleteRequest', 422, '$t:glitter-social_totp_passkey.profile.passkey_delete_failed');
        }

        var api = window.G7Core && window.G7Core.api;
        if (!api || typeof api.delete !== 'function') {
            throw failure('delete_request', 'ManagementUnavailable', 503, '$t:glitter-social_totp_passkey.profile.passkey_management_unavailable');
        }

        try {
            return await api.delete(apiPrefix + '/passkey/credentials/' + encodeURIComponent(credentialId), {
                data: { reauth_token: reauthToken },
            });
        } catch (error) {
            var status = errorStatus(error);
            var code = errorCode(error);
            var message = '$t:glitter-social_totp_passkey.profile.passkey_delete_failed';

            if (status === 419 || code === 'passkey_reauthentication_required') {
                clearPasskeyManagementReauthentication(reauthToken);
                message = '$t:glitter-social_totp_passkey.profile.passkey_management_reauthentication_expired';
            } else if (code === 'passkey_last_authenticator') {
                message = '$t:glitter-social_totp_passkey.profile.passkey_last_authenticator';
            } else if (code === 'passkey_credential_unavailable') {
                message = '$t:glitter-social_totp_passkey.profile.passkey_credential_unavailable';
                if (window.G7Core && typeof window.G7Core.dispatch === 'function') {
                    try {
                        await window.G7Core.dispatch({ handler: 'refetchDataSource', params: { dataSourceId: 'glitter_social_totp_passkey_credentials' } });
                    } catch (_) {
                        // Keep the existing list when a safe refresh is unavailable.
                    }
                }
            } else if (code === 'passkey_management_unavailable' || status === 503) {
                message = '$t:glitter-social_totp_passkey.profile.passkey_management_unavailable';
            }

            var rejected = failure('delete_request', 'PasskeyDeleteFailed', status, message);
            rejected.response = {
                status: status,
                data: {
                    message: message,
                    error_code: typeof code === 'string' ? code : '',
                },
            };
            throw rejected;
        }
    }

    var handlers = {
        passkeyLogin: authenticate,
        passkeyLoginTotp: completePasskeyTotp,
        passkeySocial: authenticate,
        passkeyReauthenticate: authenticate,
        passkeyPasswordReauthenticate: reauthenticateWithPassword,
        totpDisable: disableTotp,
        passkeyRegister: register,
        passkeyDelete: deletePasskey,
        clearPasskeyManagementReauthentication: clearPasskeyManagementReauthenticationAction,
    };

    function registerHandlers(retry) {
        var dispatcher = window.G7Core && window.G7Core.getActionDispatcher && window.G7Core.getActionDispatcher();
        if (dispatcher) {
            Object.keys(handlers).forEach(function (name) {
                dispatcher.registerHandler(identifier + '.' + name, handlers[name], { category: 'plugin', source: identifier });
            });
            bindPasskeyManagementAuthState();
            return;
        }
        if (retry) window.setTimeout(function () { registerHandlers(false); }, 100);
    }

    function initPlugin() { registerHandlers(true); }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initPlugin);
    else initPlugin();

    window.GlitterSocialTOTPPasskey = Object.freeze({
        identifier: identifier,
        apiPrefix: apiPrefix,
        providers: Object.freeze(['naver', 'kakao', 'google', 'facebook', 'github']),
        initPlugin: initPlugin,
    });
    window.__GlitterSocialTOTPPasskey = { initPlugin: initPlugin };
}(window));
