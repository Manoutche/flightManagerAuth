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

Nécessite le SDK .NET 10.

```powershell
$env:Ldap__Domain = "mondomaine.local"; dotnet run --launch-profile http
```

## Déploiement sur IIS

### 0. Pré-requis

- Serveur Windows **joint au domaine** (le microservice interroge AD avec le compte machine du serveur).
- Certificat TLS pour le nom de l'API (ex. `auth.mondomaine.local`), au format `.pfx`, émis par l'autorité interne.
- Enregistrement DNS interne vers le serveur.
- Si un ancien site IIS servait de proxy vers Docker (port 8731), le supprimer ou désactiver sa règle de réécriture.

### 1. Préparer le serveur (une seule fois, PowerShell administrateur)

```powershell
Install-WindowsFeature Web-Server -IncludeManagementTools
```

Installer le **ASP.NET Core 10.0 Runtime – Windows Hosting Bundle**
(https://dotnet.microsoft.com/download/dotnet/10.0, colonne *ASP.NET Core Runtime*, lien *Hosting Bundle*).
Le bundle d'une autre version (9 ou 11) ne suffit pas : l'application exige le runtime 10. Puis :

```powershell
net stop was /y
```
```powershell
net start w3svc
```
```powershell
Get-WebGlobalModule -Name AspNetCoreModuleV2
```

### 2. Publier (poste de développement, SDK .NET 10)

```powershell
dotnet publish "C:\Projet dev\flightManagerAuth\flightManagerAuth.csproj" -c Release -o C:\publish\flightManagerAuth
```

Copier le contenu de `C:\publish\flightManagerAuth` vers `C:\inetpub\flightManagerAuth` sur le serveur, par exemple :

```powershell
robocopy C:\publish\flightManagerAuth \NOM-SERVEUR\c$\inetpub\flightManagerAuth /E
```

### 3. Générer une clé d'API par application appelante

Voir « Déclarer une application appelante » ci-dessus. La clé va au backend, l'empreinte au microservice.

### 4. Configuration de production

Créer `C:\inetpub\flightManagerAuth\appsettings.Production.json` :

```json
{
  "AllowedHosts": "auth.mondomaine.local",
  "Ldap": { "Domain": "mondomaine.local" },
  "Security": {
    "ApiClients": [
      { "Name": "flightmanager-backend", "KeyHash": "<empreinte>" }
    ]
  },
  "Logging": {
    "EventLog": {
      "LogLevel": {
        "Default": "Warning",
        "FlightManagerApp.Controllers.AuthController": "Information"
      }
    }
  }
}
```

Le bloc `Logging:EventLog` envoie aussi les connexions réussies au journal d'événements (par défaut seuls les
échecs y vont). Pour une mise en service sans coupure, laisser `"ApiClients": []` au premier déploiement, puis le
renseigner quand tous les backends envoient `X-Api-Key` (étape 10).

### 5. Certificat

```powershell
Import-PfxCertificate -FilePath C:\certs\auth.pfx -CertStoreLocation Cert:\LocalMachine\My -Password (Read-Host -AsSecureString "Mot de passe du PFX")
```
```powershell
Get-ChildItem Cert:\LocalMachine\My | Select-Object Subject, Thumbprint, NotAfter
```

### 6. Pool d'applications

```powershell
Import-Module WebAdministration; New-WebAppPool -Name FlightManagerAuth
```
```powershell
Set-ItemProperty IIS:\AppPools\FlightManagerAuth -Name managedRuntimeVersion -Value ""
```
```powershell
Set-ItemProperty IIS:\AppPools\FlightManagerAuth -Name startMode -Value AlwaysRunning
```
```powershell
Set-ItemProperty IIS:\AppPools\FlightManagerAuth -Name processModel.idleTimeout -Value ([TimeSpan]::Zero)
```

- *No Managed Code* : ASP.NET Core n'utilise pas le CLR de IIS.
- *AlwaysRunning* et pas d'arrêt sur inactivité : sinon le compteur d'échecs par compte repart à zéro.
- Identité `ApplicationPoolIdentity` (compte machine vers AD) et **un seul processus de travail** (pas de web garden).

### 7. Site HTTPS uniquement

```powershell
New-Website -Name FlightManagerAuth -PhysicalPath C:\inetpub\flightManagerAuth -ApplicationPool FlightManagerAuth -Port 443 -Ssl -HostHeader auth.mondomaine.local
```
```powershell
(Get-WebBinding -Name FlightManagerAuth -Protocol https).AddSslCertificate("<THUMBPRINT>", "My")
```

Ajouter `-SslFlags 1` (SNI) si un autre site utilise déjà le port 443. Aucune liaison HTTP : l'application
refuse le HTTP en production (403).

### 8. Droits sur le dossier

```powershell
icacls C:\inetpub\flightManagerAuth /grant "IIS AppPool\FlightManagerAuth:(OI)(CI)RX"
```

Réseau : port 443 ouvert en entrée depuis les backends ; vers les contrôleurs de domaine, 53 (DNS), 88 (Kerberos),
389 (LDAP signé/chiffré) et 464 — normalement déjà ouverts sur un serveur joint au domaine.

### 9. Tester sur le serveur

Avec un **compte inexistant**, sans risque pour un vrai compte :

```powershell
try { Invoke-RestMethod -Uri https://auth.mondomaine.local/api/Auth/login -Method Post -ContentType application/json -Body '{"username":"zz-test-inexistant","password":"faux"}' } catch { $_.Exception.Response.StatusCode.value__; $_.ErrorDetails.Message }
```

| Résultat | Signification |
|---|---|
| 401 `invalid_credentials` | Tout fonctionne et AD répond |
| 503 `directory_unavailable` | AD injoignable : vérifier `Ldap:Domain`, DNS, flux réseau |
| 401 `invalid_api_key` | Des clés sont déclarées : ajouter `-Headers @{"X-Api-Key"="<cle>"}` |
| 500.30 / 500.31 / 502.5 | Problème de démarrage, voir étape 11 (500.31 = runtime 10 absent) |

Puis une fois avec un vrai compte : 200 avec le bloc `user`.

### 10. Raccorder les backends

Chaque backend appelle `https://auth.mondomaine.local/api/Auth/login`, envoie `X-Api-Key` (et `X-Client-IP` si
possible), utilise un timeout `HttpClient` d'environ 15 s, et affiche un message générique pour 401/403/423
(« service indisponible » pour 503). Quand tous sont à jour, renseigner `ApiClients` puis :

```powershell
Restart-WebAppPool -Name FlightManagerAuth
```

### 11. Journaux et dépannage

- Audit et erreurs : Observateur d'événements → *Journaux Windows* → *Application*, source **.NET Runtime**
  (lignes `AUDIT login application=... utilisateur=... resultat=...`).
- Échec de démarrage : même journal, source **IIS AspNetCore Module V2**. Une configuration invalide
  (`Ldap:Domain` absent, `KeyHash` mal formé) y est décrite.
- Plus de détails : créer `C:\inetpub\flightManagerAuth\logs` avec droit d'écriture pour le pool, passer
  `stdoutLogEnabled="true"` dans `web.config`, puis remettre `false` après le diagnostic.

### 12. Mettre à jour

```powershell
Set-Content C:\inetpub\flightManagerAuth\app_offline.htm "Maintenance"
```

Copier les nouveaux fichiers publiés (`appsettings.Production.json` n'en fait pas partie, il est conservé), puis :

```powershell
Remove-Item C:\inetpub\flightManagerAuth\app_offline.htm
```

Garder une copie du dossier précédent pour un retour arrière rapide.
