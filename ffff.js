const express = require('express')
const session = require('express-session')
const crypto = require('node:crypto')

const PORT = process.env.PORT || 3000
const ISSUER = process.env.ISSUER || 'http://localhost:8080/realms/myrealm'
const CLIENT_ID = process.env.CLIENT_ID
const CLIENT_SECRET = process.env.CLIENT_SECRET
const REDIRECT_URI = process.env.REDIRECT_URI || `http://localhost:${PORT}/callback`
const SCOPE = 'openid'

const app = express()
app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: true,
}))

let oidcConfig = null
let jwks = null

function decodeJwt(token) {
    const [headerB64, payloadB64] = token.split('.')
    const decode = (b64) => JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'))
    return { header: decode(headerB64), payload: decode(payloadB64) }
}

const escapeHtml = (str) => String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

const json = (data) => `<pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre>`

const DATE_CLAIMS = ['exp', 'iat', 'auth_time', 'nbf']

// Aplatit les objets imbriqués : { realm_access: { roles: [...] } } -> realm_access.roles
function flatten(obj, prefix = '') {
    return Object.entries(obj).flatMap(([key, value]) => {
        const path = prefix ? `${prefix}.${key}` : key
        if (value && typeof value === 'object' && !Array.isArray(value)) return flatten(value, path)
        return [[path, value]]
    })
}

function formatValue(key, value) {
    if (DATE_CLAIMS.includes(key)) return new Date(value * 1000).toLocaleString('fr-FR')
    if (Array.isArray(value)) return value.join(', ')
    return value
}

const table = (data) => `<table>${flatten(data)
    .map(([key, value]) => `<tr><th>${escapeHtml(key)}</th><td>${escapeHtml(formatValue(key, value))}</td></tr>`)
    .join('')}</table>`

function layout(body) {
    return `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Exo OIDC</title>
<style>
    body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 16px; color: #222; background: #fafafa; }
    a.btn { display: inline-block; background: #4f46e5; color: #fff; padding: 10px 18px; border-radius: 8px; text-decoration: none; }
    pre { background: #1e1e2e; color: #e0e0e0; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 13px; }
    h2 { margin-top: 32px; }
    table { width: 100%; border-collapse: collapse; background: #fff; font-size: 14px; }
    th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #eee; word-break: break-all; }
    th { width: 30%; color: #555; font-weight: 600; }
</style>
</head>
<body>${body}</body>
</html>`
}

async function getOidcConfig() {
    if (oidcConfig) return oidcConfig
    const res = await fetch(`${ISSUER}/.well-known/openid-configuration`)
    oidcConfig = await res.json()
    return oidcConfig
}

async function getJwks({ refresh = false } = {}) {
    if (jwks && !refresh) return jwks
    const config = await getOidcConfig()
    const res = await fetch(config.jwks_uri)
    jwks = (await res.json()).keys
    return jwks
}

async function getSigningKey(kid) {
    let key = (await getJwks()).find((k) => k.kid === kid)
    // Keycloak a pu faire une rotation de clés : on recharge le JWKS une fois
    if (!key) key = (await getJwks({ refresh: true })).find((k) => k.kid === kid)
    if (!key) throw new Error(`Aucune clé publique trouvée pour le kid ${kid}`)
    return crypto.createPublicKey({ key, format: 'jwk' })
}

const ALGORITHMS = { RS256: 'RSA-SHA256', RS384: 'RSA-SHA384', RS512: 'RSA-SHA512' }

// Vérifie la signature et les claims standards, renvoie le token décodé
async function verifyJwt(token, { audience } = {}) {
    const [headerB64, payloadB64, signatureB64] = token.split('.')
    const { header, payload } = decodeJwt(token)

    const algorithm = ALGORITHMS[header.alg]
    if (!algorithm) throw new Error(`Algorithme non supporté : ${header.alg}`)

    const key = await getSigningKey(header.kid)
    const valid = crypto.verify(
        algorithm,
        Buffer.from(`${headerB64}.${payloadB64}`),
        key,
        Buffer.from(signatureB64, 'base64url'),
    )
    if (!valid) throw new Error('Signature invalide')

    const config = await getOidcConfig()
    const now = Math.floor(Date.now() / 1000)
    if (payload.iss !== config.issuer) throw new Error(`Issuer invalide : ${payload.iss}`)
    if (payload.exp <= now) throw new Error('Token expiré')
    if (audience) {
        const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud]
        if (!aud.includes(audience)) throw new Error(`Audience invalide : ${payload.aud}`)
    }

    return { header, payload }
}

app.get('/', async (req, res) => {
    const config = await getOidcConfig()
    const state = crypto.randomBytes(16).toString('hex')
    req.session.state = state

    const params = new URLSearchParams({
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        response_type: 'code',
        scope: SCOPE,
        state,
    })

    res.send(layout(`
        <h1>Exo OIDC</h1>
        <a class="btn" href="${escapeHtml(`${config.authorization_endpoint}?${params}`)}">Se connecter</a>
    `))
})

app.get('/callback', async (req, res) => {
    const { state, code, session_state } = req.query

    if (!code || state !== req.session.state) {
        return res.status(400).send(layout('<h1>Requête invalide</h1><a href="/">Réessayer</a>'))
    }

    const config = await getOidcConfig()

    const tokenResponse = await fetch(config.token_endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            redirect_uri: REDIRECT_URI,
            state,
            session_state,
            code,
        }),
    })
    const tokens = await tokenResponse.json()

    if (!tokenResponse.ok) {
        return res.status(400).send(layout(`<h1>Erreur lors de l'échange du code</h1>${json(tokens)}<a href="/">Réessayer</a>`))
    }

    let decodedIdToken, decodedAccessToken
    try {
        decodedIdToken = await verifyJwt(tokens.id_token, { audience: CLIENT_ID })
        decodedAccessToken = await verifyJwt(tokens.access_token)
    } catch (err) {
        return res.status(401).send(layout(`<h1>Token invalide</h1><p>${escapeHtml(err.message)}</p><a href="/">Réessayer</a>`))
    }

    const userInfoResponse = await fetch(config.userinfo_endpoint, {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
    })
    const userInfo = await userInfoResponse.json()

    res.send(layout(`
        <h1>Bonjour ${escapeHtml(userInfo.name || userInfo.preferred_username)}</h1>
        <p>${escapeHtml(userInfo.email || '')} · <a href="/">Se reconnecter</a></p>
        <p>✅ Signature des tokens vérifiée</p>
        <h2>ID Token</h2>
        ${table(decodedIdToken.payload)}
        <h2>Access Token</h2>
        ${table(decodedAccessToken.payload)}
        <h2>UserInfo</h2>
        ${table(userInfo)}
    `))
})

app.listen(PORT, () => console.log(`Serveur démarré sur http://localhost:${PORT}`))
