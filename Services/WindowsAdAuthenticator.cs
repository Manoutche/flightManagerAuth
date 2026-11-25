using System.DirectoryServices.AccountManagement;
using System.Runtime.Versioning;
using FlightManagerApp.Options;
using Microsoft.Extensions.Options;

namespace FlightManagerApp.Services
{
    /// <summary>
    /// Authentification AD sous Windows (IIS). Utilise Kerberos/NTLM avec signature et chiffrement :
    /// le mot de passe ne circule jamais en clair vers le contrôleur de domaine.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class WindowsAdAuthenticator : IAdAuthenticator
    {
        private const ContextOptions SecureBind = ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing;

        private readonly LdapOptions _options;
        private readonly ILogger<WindowsAdAuthenticator> _logger;

        public WindowsAdAuthenticator(IOptions<LdapOptions> options, ILogger<WindowsAdAuthenticator> logger)
        {
            _options = options.Value;
            _logger = logger;
        }

        public async Task<AuthResult> AuthenticateAsync(string username, string password, CancellationToken cancellationToken)
        {
            try
            {
                // PrincipalContext n'a pas de timeout configurable : on borne l'attente côté appelant.
                return await Task.Run(() => Authenticate(username, password), cancellationToken)
                    .WaitAsync(TimeSpan.FromSeconds(_options.TimeoutSeconds), cancellationToken);
            }
            catch (TimeoutException)
            {
                _logger.LogError("Active Directory n'a pas répondu en {Timeout} s", _options.TimeoutSeconds);
                return AuthResult.Of(AuthStatus.Unavailable);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Erreur lors de l'appel à Active Directory");
                return AuthResult.Of(AuthStatus.Unavailable);
            }
        }

        private AuthResult Authenticate(string username, string password)
        {
            var target = string.IsNullOrWhiteSpace(_options.Server) ? _options.Domain : _options.Server;
            using var context = new PrincipalContext(ContextType.Domain, target);

            if (!context.ValidateCredentials(username, password, SecureBind))
            {
                return AuthResult.Of(GetFailureReason(context, username));
            }

            return new AuthResult(AuthStatus.Success, _options.IncludeUserDetails
                ? GetUserDetails(context, username)
                : new AdUser(username, null, null, Array.Empty<string>()));
        }

        private AuthStatus GetFailureReason(PrincipalContext context, string username)
        {
            try
            {
                using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, username);
                if (user is null) return AuthStatus.InvalidCredentials;
                if (user.Enabled == false) return AuthStatus.AccountDisabled;
                if (user.IsAccountLockedOut()) return AuthStatus.AccountLocked;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Impossible de lire l'état du compte après un échec d'authentification");
            }
            return AuthStatus.InvalidCredentials;
        }

        private AdUser GetUserDetails(PrincipalContext context, string username)
        {
            try
            {
                using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, username);
                if (user is null) return new AdUser(username, null, null, Array.Empty<string>());

                using var groups = user.GetGroups();
                var names = groups.Select(g => g.SamAccountName ?? g.Name).Where(n => !string.IsNullOrEmpty(n)).ToList();
                return new AdUser(user.SamAccountName ?? username, user.DisplayName, user.EmailAddress, names!);
            }
            catch (Exception ex)
            {
                // L'authentification a réussi : on ne la fait pas échouer pour un problème de lecture des attributs.
                _logger.LogWarning(ex, "Impossible de lire les informations de l'utilisateur {Username}", username);
                return new AdUser(username, null, null, Array.Empty<string>());
            }
        }
    }
}
