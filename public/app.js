/**
 * AuthLab POC — Frontend Alpine.js (Fase 6)
 *
 * Demuestra todos los flujos de autenticación implementados en el backend:
 * Auth, JWT, MFA/TOTP, Magic Links, RBAC, DPoP, OAuth.
 */

const API = '/api/v1';

// ── Base64url helpers (para DPoP con WebCrypto) ───────────────────────────────

function b64url(bytes) {
  return btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function jsonToB64url(obj) {
  return b64url(new TextEncoder().encode(JSON.stringify(obj)));
}

function decodeJwt(token) {
  try {
    const [, payload] = token.split('.');
    const b64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(b64.padEnd(b64.length + (4 - b64.length % 4) % 4, '=')));
  } catch { return null; }
}

// ── Alpine.js app ─────────────────────────────────────────────────────────────

function authApp() {
  return {

    // ── Navegación ─────────────────────────────────────────────────────────
    tab: 'auth',

    // ── Estado de autenticación ────────────────────────────────────────────
    accessToken: localStorage.getItem('authlab_at') ?? null,
    user: null,

    // ── Formularios (compartidos entre tabs) ───────────────────────────────
    email: '',
    password: '',

    // ── Notificaciones ─────────────────────────────────────────────────────
    toast: { visible: false, msg: '', type: 'ok' },

    // ── Inspector de respuestas API ────────────────────────────────────────
    lastRes: null,
    showRes: false,

    // ── Sesiones JWT ───────────────────────────────────────────────────────
    sessions: [],

    // ── MFA ────────────────────────────────────────────────────────────────
    mfa: {
      status: null,          // null | true | false
      secret: null,
      qrUrl: null,
      code: '',
      recoveryCodes: [],
      sessionToken: null,    // para el paso-2 del login MFA
    },

    // ── Magic Link ─────────────────────────────────────────────────────────
    magicEmail: '',

    // ── RBAC ───────────────────────────────────────────────────────────────
    rbac: {
      permissions: null,
      roles: [],
      results: {},
    },

    // ── DPoP ───────────────────────────────────────────────────────────────
    dpop: {
      keyPair: null,
      jkt: null,
      token: null,
      protectedResult: null,
    },

    // ─────────────────────────────────────────────────────────────────────
    // Init
    // ─────────────────────────────────────────────────────────────────────

    async init() {
      // Recoger AT que llega desde el callback OAuth (?at=xxx)
      const params = new URLSearchParams(location.search);
      const oauthAt = params.get('at');
      if (oauthAt) {
        this.accessToken = oauthAt;
        localStorage.setItem('authlab_at', oauthAt);
        history.replaceState({}, '', '/');
        this.showToast('Login OAuth exitoso');
      }

      const linked = params.get('linked');
      if (linked) {
        this.showToast(`Cuenta ${params.get('provider') ?? ''} vinculada correctamente`);
        history.replaceState({}, '', '/');
      }

      if (this.accessToken) {
        await this.fetchMe();
      }
    },

    // ─────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────

    showToast(msg, type = 'ok') {
      this.toast = { visible: true, msg, type };
      setTimeout(() => { this.toast.visible = false; }, 4500);
    },

    async api(method, path, body = null, extraHeaders = {}) {
      const headers = { 'Content-Type': 'application/json', ...extraHeaders };
      if (this.accessToken) headers['Authorization'] = `Bearer ${this.accessToken}`;

      const r = await fetch(`${API}${path}`, {
        method,
        headers,
        credentials: 'include',   // envía la cookie HttpOnly del RT
        body: body != null ? JSON.stringify(body) : undefined,
      });

      const data = await r.json().catch(() => ({}));
      this.lastRes = { status: r.status, ok: r.ok, path: `${method} ${path}`, data };
      return { ok: r.ok, status: r.status, data };
    },

    get decoded() {
      return this.accessToken ? decodeJwt(this.accessToken) : null;
    },

    get tokenExpTime() {
      const d = this.decoded;
      if (!d?.exp) return null;
      const exp = new Date(d.exp * 1000);
      const now = new Date();
      if (exp < now) return 'EXPIRADO';
      const secs = Math.floor((exp - now) / 1000);
      return secs < 60 ? `${secs}s` : `${Math.floor(secs / 60)}m ${secs % 60}s`;
    },

    get tokenExpired() {
      const d = this.decoded;
      return d?.exp ? d.exp < Math.floor(Date.now() / 1000) : false;
    },

    // ─────────────────────────────────────────────────────────────────────
    // Auth
    // ─────────────────────────────────────────────────────────────────────

    async register() {
      const { ok, data } = await this.api('POST', '/auth/register', {
        email: this.email,
        password: this.password,
      });
      if (ok) {
        this.showToast('Registro exitoso — link de verificación en la consola del servidor');
      } else {
        this.showToast(data.error ?? 'Error en registro', 'err');
      }
    },

    async doLogin() {
      const { ok, data, status } = await this.api('POST', '/auth/login', {
        email: this.email,
        password: this.password,
      });

      if (status === 200) {
        this.accessToken = data.accessToken;
        localStorage.setItem('authlab_at', this.accessToken);
        await this.fetchMe();
        this.showToast(`Bienvenido, ${this.user?.email ?? ''}`);
        this.tab = 'jwt';
      } else if (data.code === 'MFA_REQUERIDO') {
        this.mfa.sessionToken = data.mfa_session_token ?? null;
        this.showToast('MFA requerido — introduce el código TOTP', 'warn');
        this.tab = 'mfa';
      } else {
        this.showToast(data.error ?? 'Credenciales incorrectas', 'err');
      }
    },

    async logout() {
      await this.api('POST', '/auth/logout');
      this.accessToken = null;
      this.user = null;
      localStorage.removeItem('authlab_at');
      this.tab = 'auth';
      this.showToast('Sesión cerrada');
    },

    async fetchMe() {
      const { ok, data } = await this.api('GET', '/user/me');
      if (ok) {
        this.user = data;
      } else {
        this.accessToken = null;
        localStorage.removeItem('authlab_at');
      }
    },

    // ─────────────────────────────────────────────────────────────────────
    // JWT / Sesiones
    // ─────────────────────────────────────────────────────────────────────

    async refresh() {
      const { ok, data } = await this.api('POST', '/jwt/refresh');
      if (ok) {
        this.accessToken = data.accessToken;
        localStorage.setItem('authlab_at', this.accessToken);
        this.showToast('Token renovado — nuevo AT emitido con el RT de la cookie');
      } else {
        this.showToast(data.error ?? 'Error al renovar — inicia sesión de nuevo', 'err');
        this.accessToken = null;
        this.user = null;
        localStorage.removeItem('authlab_at');
      }
    },

    async fetchSessions() {
      const { ok, data } = await this.api('GET', '/jwt/sessions');
      if (ok) this.sessions = data.sessions ?? [];
      else this.showToast(data.error ?? 'Error', 'err');
    },

    async revokeAll() {
      if (!confirm('¿Revocar TODAS las sesiones? Tendrás que volver a iniciar sesión.')) return;
      const { ok } = await this.api('POST', '/jwt/logout-all');
      if (ok) {
        this.accessToken = null;
        this.user = null;
        localStorage.removeItem('authlab_at');
        this.sessions = [];
        this.tab = 'auth';
        this.showToast('Todas las sesiones revocadas');
      }
    },

    // ─────────────────────────────────────────────────────────────────────
    // MFA / TOTP
    // ─────────────────────────────────────────────────────────────────────

    async fetchMfaStatus() {
      const { ok, data } = await this.api('GET', '/mfa/status');
      if (ok) this.mfa.status = data.mfa_enabled === 1;
    },

    async mfaSetup() {
      const { ok, data } = await this.api('POST', '/mfa/setup');
      if (ok) {
        this.mfa.secret = data.secret;
        this.mfa.qrUrl = data.qrCodeDataUrl;
        this.showToast('Escanea el QR con Google Authenticator o Authy');
      } else {
        this.showToast(data.error ?? 'Error', 'err');
      }
    },

    async mfaEnable() {
      const { ok, data } = await this.api('POST', '/mfa/enable', { code: this.mfa.code });
      if (ok) {
        this.mfa.status = true;
        this.mfa.recoveryCodes = data.recoveryCodes ?? [];
        this.mfa.code = '';
        this.showToast('MFA activado — guarda los códigos de recuperación');
      } else {
        this.showToast(data.error ?? 'Código incorrecto', 'err');
      }
    },

    async mfaDisable() {
      const { ok, data } = await this.api('POST', '/mfa/disable', { code: this.mfa.code });
      if (ok) {
        this.mfa.status = false;
        this.mfa.secret = null;
        this.mfa.qrUrl = null;
        this.mfa.code = '';
        this.showToast('MFA desactivado');
      } else {
        this.showToast(data.error ?? 'Error', 'err');
      }
    },

    async mfaVerifyLogin() {
      // Paso-2 del login cuando el servidor devuelve MFA_REQUERIDO
      const { ok, data } = await this.api('POST', '/mfa/verify', {
        code: this.mfa.code,
        mfa_session_token: this.mfa.sessionToken,
      });
      if (ok) {
        this.accessToken = data.accessToken;
        localStorage.setItem('authlab_at', this.accessToken);
        await this.fetchMe();
        this.mfa.sessionToken = null;
        this.mfa.code = '';
        this.showToast('MFA verificado — sesión iniciada');
        this.tab = 'jwt';
      } else {
        this.showToast(data.error ?? 'Código incorrecto', 'err');
      }
    },

    // ─────────────────────────────────────────────────────────────────────
    // Magic Link
    // ─────────────────────────────────────────────────────────────────────

    async requestMagicLink() {
      const { ok, data } = await this.api('POST', '/magic/request', { email: this.magicEmail });
      if (ok) {
        this.showToast('Magic link "enviado" — busca la URL en la consola del servidor (dev mode)');
      } else {
        this.showToast(data.error ?? 'Error', 'err');
      }
    },

    // ─────────────────────────────────────────────────────────────────────
    // RBAC
    // ─────────────────────────────────────────────────────────────────────

    async fetchPermissions() {
      const { ok, data } = await this.api('GET', '/rbac/my-permissions');
      if (ok) {
        this.rbac.permissions = data.permisos ?? [];
        this.rbac.roles = data.roles ?? [];
      } else {
        this.showToast(data.error ?? 'Error (¿estás autenticado?)', 'err');
      }
    },

    async tryEndpoint(method, path) {
      const key = `${method} ${path}`;
      const { status, data } = await this.api(method, path);
      this.rbac.results = {
        ...this.rbac.results,
        [key]: { status, ok: status < 300, msg: data.acceso ?? data.error ?? data.code ?? '' },
      };
    },

    hasPerm(perm) {
      return this.rbac.permissions?.includes(perm) ?? false;
    },

    // ─────────────────────────────────────────────────────────────────────
    // DPoP — Demonstrating Proof of Possession
    // ─────────────────────────────────────────────────────────────────────

    async generateDpopKey() {
      this.dpop.keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,          // exportable (necesario para incluir JWK en el proof)
        ['sign', 'verify'],
      );
      // Calcular JWK thumbprint (RFC 7638)
      const jwk = await crypto.subtle.exportKey('jwk', this.dpop.keyPair.publicKey);
      const canonical = JSON.stringify({ crv: jwk.crv, kty: 'EC', x: jwk.x, y: jwk.y });
      const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
      this.dpop.jkt = b64url(new Uint8Array(hash));
      this.dpop.token = null;
      this.dpop.protectedResult = null;
      this.showToast('Par de claves ECDSA P-256 generado en el navegador (WebCrypto API)');
    },

    async _buildDpopProof(htm, htu, accessToken = null) {
      const jwk = await crypto.subtle.exportKey('jwk', this.dpop.keyPair.publicKey);
      const payload = { jti: crypto.randomUUID(), htm, htu, iat: Math.floor(Date.now() / 1000) };

      if (accessToken) {
        const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken));
        payload.ath = b64url(new Uint8Array(hash));
      }

      const headerB64  = jsonToB64url({ alg: 'ES256', typ: 'dpop+jwt', jwk });
      const payloadB64 = jsonToB64url(payload);
      const sigInput = `${headerB64}.${payloadB64}`;

      // WebCrypto ECDSA devuelve firma en formato R||S (ieee-p1363) — el que necesita JWT
      const sig = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        this.dpop.keyPair.privateKey,
        new TextEncoder().encode(sigInput),
      );

      return `${sigInput}.${b64url(new Uint8Array(sig))}`;
    },

    async getDpopToken() {
      if (!this.dpop.keyPair) {
        this.showToast('Genera primero el par de claves (Paso 1)', 'err');
        return;
      }
      if (!this.email || !this.password) {
        this.showToast('Introduce email y password en el tab Auth', 'warn');
        return;
      }
      const htu   = `${location.origin}/api/v1/dpop/token`;
      const proof = await this._buildDpopProof('POST', htu);

      const r = await fetch(`${API}/dpop/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'DPoP': proof },
        body: JSON.stringify({ email: this.email, password: this.password }),
      });
      const data = await r.json();
      this.lastRes = { status: r.status, ok: r.ok, path: 'POST /dpop/token', data };

      if (r.ok) {
        this.dpop.token = data.access_token;
        this.showToast('AT DPoP-bound obtenido — vinculado a la clave privada del navegador');
      } else {
        this.showToast(data.error ?? 'Error', 'err');
      }
    },

    async dpopAccessProtected() {
      if (!this.dpop.token || !this.dpop.keyPair) {
        this.showToast('Necesitas un AT DPoP primero (Paso 2)', 'err');
        return;
      }
      const htu   = `${location.origin}/api/v1/dpop/protected`;
      const proof = await this._buildDpopProof('GET', htu, this.dpop.token);

      const r = await fetch(`${API}/dpop/protected`, {
        headers: { 'Authorization': `DPoP ${this.dpop.token}`, 'DPoP': proof },
      });
      const data = await r.json();
      this.lastRes = { status: r.status, ok: r.ok, path: 'GET /dpop/protected', data };
      this.dpop.protectedResult = { ok: r.ok, data };

      if (r.ok) {
        this.showToast('Acceso DPoP concedido — prueba de posesión de clave exitosa');
      } else {
        this.showToast(data.error ?? 'Error', 'err');
      }
    },

    // ─────────────────────────────────────────────────────────────────────
    // OAuth
    // ─────────────────────────────────────────────────────────────────────

    startOAuth(provider) {
      window.location.href = `${API}/oauth/${provider}/start`;
    },
  };
}
