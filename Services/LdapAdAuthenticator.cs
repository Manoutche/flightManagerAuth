using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;
using FlightManagerApp.Options;
using Microsoft.Extensions.Options;

namespace FlightManagerApp.Services
{
    /// <summary>
    /// Authentification AD hors Windows, par bind LDAP. Utilise LDAPS par défaut (port 636).
    /// </summary>
    public sealed class LdapAdAuthenticator : IAdAuthenticator
    {
        private readonly LdapOptions _options;
        private readonly ILogger<LdapAdAuthenticator> _logger;

        public LdapAdAuthenticator(IOptions<LdapOptions> options, ILogger<LdapAdAuthenticator> logger)
        {
            _options = options.Value;
            _logger = logger;
        }

        public Task<AuthResult> AuthenticateAsync(string username, string password, CancellationToken cancellationToken)
            => Task.Run(() => Authenticate(username, password), cancellationToken);

        private AuthResult Authenticate(string username, string password)
        {
            try
            {
                using var connection = new LdapConnection(new LdapDirectoryIdentifier(_options.Server, _options.Port));
                connection.SessionOptions.ProtocolVersion = 3;
                connection.SessionOptions.SecureSocketLayer = _options.UseSsl;
                connection.AuthType = AuthType.Basic;
                connection.Timeout = TimeSpan.FromSeconds(_options.TimeoutSeconds);

                try
                {
                    connection.Bind(new NetworkCredential($"{username}@{_options.Domain}", password));
                }
                catch (LdapException ex) when (ex.ErrorCode == 49) // invalidCredentials
                {
                    return AuthResult.Of(MapAdSubCode(ex.ServerErrorMessage));
                }

                return new AuthResult(AuthStatus.Success, _options.IncludeUserDetails
                    ? GetUserDetails(connection, username)
                    : new AdUser(username, null, null, Array.Empty<string>()));
            }
            catch (LdapException ex)
            {
                _logger.LogError(ex, "Erreur LDAP (code {Code}) vers {Server}:{Port}", ex.ErrorCode, _options.Server, _options.Port);
                return AuthResult.Of(AuthStatus.Unavailable);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de l'appel LDAP");
                return AuthResult.Of(AuthStatus.Unavailable);
            }
        }

        /// <summary>Traduit le sous-code AD présent dans le message d'erreur ("... data 775, ...").</summary>
        private static AuthStatus MapAdSubCode(string? serverMessage)
        {
            var msg = serverMessage ?? string.Empty;
            if (msg.Contains("data 775", StringComparison.OrdinalIgnoreCase)) return AuthStatus.AccountLocked;
            if (msg.Contains("data 533", StringComparison.OrdinalIgnoreCase) ||
                msg.Contains("data 701", StringComparison.OrdinalIgnoreCase)) return AuthStatus.AccountDisabled;
            if (msg.Contains("data 532", StringComparison.OrdinalIgnoreCase) ||
                msg.Contains("data 773", StringComparison.OrdinalIgnoreCase)) return AuthStatus.PasswordExpired;
            return AuthStatus.InvalidCredentials;
        }

        private AdUser GetUserDetails(LdapConnection connection, string username)
        {
            try
            {
                var baseDn = string.Join(",", _options.Domain.Split('.', StringSplitOptions.RemoveEmptyEntries).Select(p => "DC=" + p));
                var request = new SearchRequest(baseDn, $"(&(objectCategory=person)(sAMAccountName={EscapeFilter(username)}))",
                    SearchScope.Subtree, "sAMAccountName", "displayName", "mail", "memberOf");
                var response = (SearchResponse)connection.SendRequest(request);
                if (response.Entries.Count == 0) return new AdUser(username, null, null, Array.Empty<string>());

                var entry = response.Entries[0];
                var groups = new List<string>();
                if (entry.Attributes["memberOf"] is { } memberOf)
                {
                    foreach (var dn in memberOf.GetValues(typeof(string)).Cast<string>())
                    {
                        var first = dn.Split(',')[0];
                        groups.Add(first.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ? first[3..] : first);
                    }
                }
                return new AdUser(Attr(entry, "sAMAccountName") ?? username, Attr(entry, "displayName"), Attr(entry, "mail"), groups);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Impossible de lire les informations de l'utilisateur {Username}", username);
                return new AdUser(username, null, null, Array.Empty<string>());
            }
        }

        private static string? Attr(SearchResultEntry entry, string name)
            => entry.Attributes[name] is { Count: > 0 } a ? a[0] as string : null;

        /// <summary>Échappement RFC 4515 des valeurs insérées dans un filtre LDAP.</summary>
        private static string EscapeFilter(string value)
        {
            var sb = new StringBuilder(value.Length);
            foreach (var c in value)
            {
                sb.Append(c switch
                {
                    '\\' => @"\5c",
                    '*' => @"\2a",
                    '(' => @"\28",
                    ')' => @"\29",
                    '\0' => @"\00",
                    _ => c.ToString(),
                });
            }
            return sb.ToString();
        }
    }
}
