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

function decodeJwt(token) {
    const [headerB64, payloadB64] = token.split('.')
    const decode = (b64) => JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'))
    return { header: decode(headerB64), payload: decode(payloadB64) }
}

async function getOidcConfig() {
    if (oidcConfig) return oidcConfig
    const res = await fetch(`${ISSUER}/.well-known/openid-configuration`)
    oidcConfig = await res.json()
    return oidcConfig
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

    res.send(`<a href="${config.authorization_endpoint}?${params}">Se connecter</a>`)
})

app.get('/callback', async (req, res) => {
    const { state, code, session_state } = req.query

    if (!code || state !== req.session.state) {
        return res.status(400).send('Requête invalide (code ou state manquant/incorrect)')
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
        return res.status(400).send(`Erreur lors de l'échange du code: ${JSON.stringify(tokens)}`)
    }

    const decodedIdToken = decodeJwt(tokens.id_token)
    const decodedAccessToken = decodeJwt(tokens.access_token)

    const userInfoResponse = await fetch(config.userinfo_endpoint, {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
    })
    const userInfo = await userInfoResponse.json()

    res.send(`
        <h2>ID Token (décodé)</h2>
        <pre>${JSON.stringify(decodedIdToken, null, 2)}</pre>
        <h2>Access Token (décodé)</h2>
        <pre>${JSON.stringify(decodedAccessToken, null, 2)}</pre>
        <h2>UserInfo</h2>
        <pre>${JSON.stringify(userInfo, null, 2)}</pre>
    `)
})

app.listen(PORT, () => console.log(`Serveur démarré sur http://localhost:${PORT}`))
