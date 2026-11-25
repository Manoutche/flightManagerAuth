using System.Security.Cryptography;
using System.Text;
using FlightManagerApp.Options;
using Microsoft.Extensions.Options;

namespace FlightManagerApp.Security
{
    /// <summary>
    /// Vérifie que l'appelant est une application déclarée (en-tête X-Api-Key).
    /// Seule l'empreinte SHA-256 des clés est stockée dans la configuration.
    /// </summary>
    public sealed class ApiKeyMiddleware
    {
        public const string HeaderName = "X-Api-Key";
        public const string ClientItemKey = "ApiClientName";
        public const string AnonymousClient = "non-identifie";

        private readonly RequestDelegate _next;
        private readonly IOptionsMonitor<SecurityOptions> _options;
        private readonly ILogger<ApiKeyMiddleware> _logger;

        public ApiKeyMiddleware(RequestDelegate next, IOptionsMonitor<SecurityOptions> options, ILogger<ApiKeyMiddleware> logger)
        {
            _next = next;
            _options = options;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var clients = _options.CurrentValue.ApiClients;
            if (clients.Count == 0)
            {
                // Mode de transition : aucune clé configurée.
                context.Items[ClientItemKey] = AnonymousClient;
                await _next(context);
                return;
            }

            var provided = context.Request.Headers[HeaderName].ToString();
            var client = string.IsNullOrEmpty(provided) ? null : FindClient(clients, provided);
            if (client is null)
            {
                _logger.LogWarning("Appel refusé : clé d'API absente ou invalide depuis {RemoteIp}", context.Connection.RemoteIpAddress);
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new
                {
                    success = false,
                    error = "invalid_api_key",
                    message = "Application appelante non autorisée.",
                });
                return;
            }

            context.Items[ClientItemKey] = client.Name;
            await _next(context);
        }

        private static ApiClient? FindClient(List<ApiClient> clients, string providedKey)
        {
            var providedHash = SHA256.HashData(Encoding.UTF8.GetBytes(providedKey));
            ApiClient? match = null;
            foreach (var client in clients)
            {
                // Comparaison à temps constant ; on parcourt toute la liste dans tous les cas.
                if (CryptographicOperations.FixedTimeEquals(providedHash, Convert.FromHexString(client.KeyHash)))
                {
                    match = client;
                }
            }
            return match;
        }

        public static bool IsValidKeyHash(string? hash)
            => hash is { Length: 64 } && hash.All(Uri.IsHexDigit);
    }
}
