# Exo OIDC — Authorization Code Flow

Petit serveur Express qui implémente le flow OpenID Connect « Authorization Code » avec Keycloak, puis affiche le contenu de l'ID Token, de l'Access Token et du endpoint UserInfo.

## Prérequis

- Node.js 20.6 ou plus récent (pour l'option `--env-file`)
- Un serveur Keycloak avec :
  - un realm
  - un client **confidentiel** (Client authentication activé) avec le flow « Standard flow » activé
  - `http://localhost:3000/callback` dans les **Valid redirect URIs** du client
  - un utilisateur pour se connecter

## Installation

```bash
npm install
cp .env.example .env
```

Puis remplir le fichier `.env` :

| Variable        | Description                                             | Exemple                                  |
| --------------- | ------------------------------------------------------- | ---------------------------------------- |
| `PORT`          | Port du serveur                                         | `3000`                                   |
| `ISSUER`        | URL du realm Keycloak                                   | `http://localhost:8080/realms/myrealm`   |
| `CLIENT_ID`     | Identifiant du client Keycloak                          | `mon-client`                             |
| `CLIENT_SECRET` | Secret du client (onglet *Credentials* dans Keycloak)   | `xxxxxxxx`                               |
| `REDIRECT_URI`  | URL de callback, identique à celle configurée dans Keycloak | `http://localhost:3000/callback`     |

## Lancement

```bash
npm start
```

Ouvrir ensuite http://localhost:3000 et cliquer sur **Se connecter**.

## Déroulé du flow

1. `/` génère un `state` aléatoire, le stocke en session et redirige vers la page de login Keycloak.
2. Après le login, Keycloak redirige vers `/callback` avec un `code` et le `state`.
3. Le serveur vérifie le `state`, puis échange le `code` contre les tokens sur le `token_endpoint`.
4. La signature des tokens est vérifiée avec les clés publiques du realm (`jwks_uri`), ainsi que l'issuer, l'expiration et l'audience de l'ID Token.
5. Le endpoint `userinfo` est appelé avec l'Access Token.
6. La page affiche les informations dans des tableaux.
