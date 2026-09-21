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
    const { state, code } = req.query

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
            code,
        }),
    })
    const tokens = await tokenResponse.json()

    if (!tokenResponse.ok) {
        return res.status(400).send(`Erreur lors de l'échange du code: ${JSON.stringify(tokens)}`)
    }

    const userInfoResponse = await fetch(config.userinfo_endpoint, {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
    })
    const userInfo = await userInfoResponse.json()

    res.send(`<pre>${JSON.stringify(userInfo, null, 2)}</pre>`)
})

app.listen(PORT, () => console.log(`Serveur démarré sur http://localhost:${PORT}`))
