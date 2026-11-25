using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using FlightManagerApp.Options;
using FlightManagerApp.Security;
using FlightManagerApp.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace FlightManagerApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public sealed partial class AuthController : ControllerBase
    {
        /// <summary>En-tête facultatif où le backend appelant transmet l'IP de l'utilisateur final (pour l'audit).</summary>
        public const string EndUserIpHeader = "X-Client-IP";

        private readonly IAdAuthenticator _authenticator;
        private readonly LoginAttemptTracker _attempts;
        private readonly LdapOptions _ldap;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IAdAuthenticator authenticator, LoginAttemptTracker attempts,
            IOptions<LdapOptions> ldap, ILogger<AuthController> logger)
        {
            _authenticator = authenticator;
            _attempts = attempts;
            _ldap = ldap.Value;
            _logger = logger;
        }

        [HttpPost("login")]
        [Consumes("application/json")]
        [EnableRateLimiting(RateLimitPolicies.PerClient)]
        public async Task<IActionResult> Authenticate([FromBody] LoginRequest request, CancellationToken cancellationToken)
        {
            var client = HttpContext.Items[ApiKeyMiddleware.ClientItemKey] as string ?? ApiKeyMiddleware.AnonymousClient;
            var endUserIp = Request.Headers[EndUserIpHeader].ToString() is { Length: > 0 and <= 45 } ip ? ip : "-";

            var username = NormalizeUsername(request.Username);
            if (username is null || string.IsNullOrWhiteSpace(request.Password))
            {
                return Failure(StatusCodes.Status400BadRequest, "invalid_request", "Nom d'utilisateur ou mot de passe invalide.");
            }

            if (_attempts.IsBlocked(username))
            {
                Audit(client, username, endUserIp, "too_many_attempts");
                return Failure(StatusCodes.Status429TooManyRequests, "too_many_attempts",
                    "Trop de tentatives échouées pour ce compte. Réessayez plus tard.");
            }

            var result = await _authenticator.AuthenticateAsync(username, request.Password, cancellationToken);

            if (result.Status == AuthStatus.InvalidCredentials) _attempts.RegisterFailure(username);
            else if (result.Status == AuthStatus.Success) _attempts.Reset(username);

            Audit(client, username, endUserIp, result.Status.ToString());

            return result.Status switch
            {
                AuthStatus.Success => Ok(new
                {
                    success = true,
                    message = "Authentification réussie.",
                    user = result.User,
                }),
                AuthStatus.InvalidCredentials => Failure(StatusCodes.Status401Unauthorized, "invalid_credentials",
                    "Le mot de passe ou le nom d'utilisateur est incorrect."),
                AuthStatus.AccountLocked => Failure(StatusCodes.Status423Locked, "account_locked",
                    "Le compte est verrouillé dans Active Directory."),
                AuthStatus.AccountDisabled => Failure(StatusCodes.Status403Forbidden, "account_disabled",
                    "Le compte est désactivé ou expiré."),
                AuthStatus.PasswordExpired => Failure(StatusCodes.Status403Forbidden, "password_expired",
                    "Le mot de passe a expiré et doit être changé."),
                _ => Failure(StatusCodes.Status503ServiceUnavailable, "directory_unavailable",
                    "Active Directory est momentanément indisponible."),
            };
        }

        /// <summary>
        /// Accepte "login", "DOMAINE\login" ou "login@domaine" et renvoie le sAMAccountName,
        /// ou null si le format est invalide (empêche d'injecter un autre domaine dans le bind).
        /// </summary>
        private string? NormalizeUsername(string? raw)
        {
            var value = raw?.Trim() ?? string.Empty;

            var backslash = value.IndexOf('\\');
            if (backslash >= 0) value = value[(backslash + 1)..];

            var suffix = "@" + _ldap.Domain;
            if (value.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) value = value[..^suffix.Length];

            return SamAccountNameRegex().IsMatch(value) ? value : null;
        }

        [GeneratedRegex(@"^[A-Za-z0-9._-]{1,64}$")]
        private static partial Regex SamAccountNameRegex();

        private void Audit(string client, string username, string endUserIp, string outcome)
        {
            var level = outcome == nameof(AuthStatus.Success) ? LogLevel.Information : LogLevel.Warning;
            _logger.Log(level, "AUDIT login application={Client} utilisateur={Username} ipUtilisateur={EndUserIp} ipAppelant={CallerIp} resultat={Outcome}",
                client, username, endUserIp, HttpContext.Connection.RemoteIpAddress, outcome);
        }

        private ObjectResult Failure(int statusCode, string error, string message)
            => StatusCode(statusCode, new { success = false, error, message });
    }

    public sealed class LoginRequest
    {
        [Required, StringLength(256)]
        public string Username { get; set; } = string.Empty;

        [Required, StringLength(256)]
        public string Password { get; set; } = string.Empty;
    }

    public static class RateLimitPolicies
    {
        public const string PerClient = "per-client";
    }
}
