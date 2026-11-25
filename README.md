# flightManagerAuth — microservice d'authentification Active Directory

Les backends des applications internes envoient le login et le mot de passe AD saisis par l'utilisateur ;
le microservice les vérifie auprès d'Active Directory et répond si l'accès est accordé.

```
Navigateur ──HTTPS──► Backend de l'app ──HTTPS + X-Api-Key──► flightManagerAuth (IIS) ──Kerberos signé/chiffré──► AD
```

Le microservice ne doit **jamais** être appelé directement depuis un navigateur (pas de CORS).

## Contrat de l'API

`POST /api/Auth/login` — `Content-Type: application/json`

| En-tête | Obligatoire | Rôle |
|---|---|---|
| `X-Api-Key` | oui dès qu'une application est déclarée | Identifie l'application appelante |
| `X-Client-IP` | non | IP de l'utilisateur final, uniquement pour l'audit |

```json
{ "username": "jdupont", "password": "..." }
```

`username` accepte `jdupont`, `DOMAINE\jdupont` ou `jdupont@<domaine configuré>`.

| Code | `error` | Signification |
|---|---|---|
| 200 | — | Accès accordé. `success: true` + `user` (`username`, `displayName`, `email`, `groups`) |
| 400 | `invalid_request` | Corps invalide ou nom d'utilisateur au mauvais format |
| 401 | `invalid_credentials` | Identifiants incorrects |
| 401 | `invalid_api_key` | Application appelante non déclarée |
| 403 | `account_disabled` / `password_expired` | Compte désactivé/expiré, mot de passe à changer |
| 403 | `https_required` | Requête reçue en HTTP |
| 423 | `account_locked` | Compte verrouillé dans AD |
| 429 | `too_many_attempts` | Trop d'échecs sur ce compte (blocage temporaire) |
| 429 | `too_many_requests` | Trop de requêtes de cette application |
| 503 | `directory_unavailable` | AD injoignable ou trop lent : ne pas afficher « mot de passe incorrect » |

Toutes les réponses contiennent `success` et `message`. Côté backend, afficher à l'utilisateur un message
générique pour 401/403/423 afin de ne pas révéler l'état des comptes.

Prévoir un timeout `HttpClient` d'environ 15 s côté backend (le microservice abandonne AD après `Ldap:TimeoutSeconds`).

## Configuration

Sources, par ordre de priorité croissante : `appsettings.json`, `appsettings.{Environnement}.json`,
variables d'environnement (`Ldap__Domain`, `Security__ApiClients__0__Name`, ...).
Les anciennes variables `LDAP_DOMAIN` / `LDAP_SERVER` restent acceptées.

| Clé | Défaut | Description |
|---|---|---|
| `Ldap:Domain` | — | **Obligatoire.** Domaine AD |
| `Ldap:Server` | — | DC à utiliser. Facultatif sous Windows (localisation automatique) |
| `Ldap:Port` / `Ldap:UseSsl` | 636 / true | Hors Windows uniquement (LDAPS) |
| `Ldap:TimeoutSeconds` | 10 | Délai max d'un appel AD avant 503 |
| `Ldap:IncludeUserDetails` | true | Renvoie nom, e-mail et groupes directs |
| `Security:RequireHttps` | true | Refuse le HTTP (false en Development) |
| `Security:ApiClients` | [] | Applications autorisées (`Name`, `KeyHash`). Vide = tout appelant accepté (transition) |
| `Security:MaxFailuresPerUser` | 5 | Échecs avant blocage. **Doit rester sous le seuil de verrouillage AD** |
| `Security:FailureWindowMinutes` | 15 | Fenêtre de comptage et durée du blocage |
| `Security:RequestsPerClientPerMinute` | 120 | Débit max par application |

En production, créer `appsettings.Production.json` **sur le serveur** à partir de
`appsettings.Production.example.json` (ce fichier n'est pas versionné).

### Déclarer une application appelante

Générer une clé et son empreinte (PowerShell) :

```powershell
$b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); $key = [Convert]::ToBase64String($b); $hash = -join ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($key)) | ForEach-Object { $_.ToString('x2') }); "Cle (a donner au backend) : $key"; "KeyHash (appsettings.Production.json) : $hash"
```

- La **clé** va dans la configuration du backend appelant, qui l'envoie dans `X-Api-Key`.
- L'**empreinte** va dans `Security:ApiClients` du microservice. La clé elle-même n'y est jamais stockée.
- Pour révoquer une application : retirer son entrée et recycler le pool IIS.

Mise en place sans coupure : déployer avec `ApiClients` vide, faire envoyer `X-Api-Key` par chaque backend,
puis renseigner `ApiClients`.

## Développement local

```powershell
$env:Ldap__Domain = "mondomaine.local"; dotnet run --launch-profile http
```

## Déploiement sur IIS

Pré-requis : serveur Windows **joint au domaine**, certificat TLS pour le nom d'hôte de l'API.

1. Installer IIS et la restriction d'IP :
   ```powershell
   Install-WindowsFeature Web-Server, Web-IP-Security -IncludeManagementTools
   ```
2. Installer le **ASP.NET Core Hosting Bundle** de la version du projet (9.x, 10.x après migration), puis `net stop was /y` et `net start w3svc`.
3. Publier :
   ```powershell
   dotnet publish -c Release -o C:\inetpub\flightManagerAuth
   ```
4. Créer `C:\inetpub\flightManagerAuth\appsettings.Production.json` (domaine, `AllowedHosts`, applications).
5. Pool d'applications sans code managé et site HTTPS uniquement :
   ```powershell
   Import-Module WebAdministration; New-WebAppPool -Name FlightManagerAuth; Set-ItemProperty IIS:\AppPools\FlightManagerAuth -Name managedRuntimeVersion -Value ""
   ```
   ```powershell
   New-Website -Name FlightManagerAuth -PhysicalPath C:\inetpub\flightManagerAuth -ApplicationPool FlightManagerAuth -Port 443 -Ssl -HostHeader auth.mondomaine.local
   ```
   ```powershell
   (Get-WebBinding -Name FlightManagerAuth -Protocol https).AddSslCertificate("<EMPREINTE_CERTIFICAT>", "My")
   ```
6. Droits de lecture pour le pool :
   ```powershell
   icacls C:\inetpub\flightManagerAuth /grant "IIS AppPool\FlightManagerAuth:(OI)(CI)RX"
   ```
7. N'autoriser que les serveurs backends (IP and Domain Restrictions) :
   ```powershell
   Set-WebConfigurationProperty -PSPath IIS:\ -Location FlightManagerAuth -Filter system.webServer/security/ipSecurity -Name allowUnlisted -Value $false
   ```
   ```powershell
   Add-WebConfiguration -PSPath IIS:\ -Location FlightManagerAuth -Filter system.webServer/security/ipSecurity -Value @{ipAddress="10.0.0.10"; allowed="true"}
   ```
   (répéter la seconde commande pour chaque serveur backend).
8. Tester :
   ```powershell
   Invoke-RestMethod -Uri https://auth.mondomaine.local/api/Auth/login -Method Post -ContentType application/json -Headers @{"X-Api-Key"="<cle>"} -Body '{"username":"compte.test","password":"<mot_de_passe_test>"}'
   ```

Dépannage : erreurs 500.30 / 500.31 / 502.5 → Observateur d'événements, journal *Application*, source
*IIS AspNetCore Module V2*. Une erreur de configuration (`Ldap:Domain` absent, `KeyHash` invalide) empêche le
démarrage et y est décrite. Pour plus de détails, passer temporairement `stdoutLogEnabled="true"` dans
`web.config` (créer le dossier `logs` avec droit d'écriture pour le pool).

Les lignes d'audit (`AUDIT login application=... utilisateur=... resultat=...`) sont émises par `ILogger` ;
brancher un fournisseur de journaux (journal d'événements Windows, fichier, SIEM) selon vos besoins.
