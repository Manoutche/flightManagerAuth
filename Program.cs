using System.Threading.RateLimiting;
using FlightManagerApp.Controllers;
using FlightManagerApp.Options;
using FlightManagerApp.Security;
using FlightManagerApp.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(k => k.AddServerHeader = false);

// --- Configuration -------------------------------------------------------
// Sources : appsettings.json, appsettings.{Environnement}.json, variables d'environnement
// (ex. Ldap__Domain). Les anciennes variables LDAP_DOMAIN / LDAP_SERVER restent acceptées.
builder.Services.AddOptions<LdapOptions>()
    .Bind(builder.Configuration.GetSection(LdapOptions.Section))
    .PostConfigure(o =>
    {
        if (string.IsNullOrWhiteSpace(o.Domain)) o.Domain = builder.Configuration["LDAP_DOMAIN"] ?? string.Empty;
        if (string.IsNullOrWhiteSpace(o.Server)) o.Server = builder.Configuration["LDAP_SERVER"];
    })
    .Validate(o => !string.IsNullOrWhiteSpace(o.Domain), "Ldap:Domain (ou LDAP_DOMAIN) est obligatoire.")
    .Validate(o => OperatingSystem.IsWindows() || !string.IsNullOrWhiteSpace(o.Server), "Ldap:Server est obligatoire hors Windows.")
    .Validate(o => o.TimeoutSeconds is > 0 and <= 120, "Ldap:TimeoutSeconds doit être entre 1 et 120.")
    .ValidateOnStart();

builder.Services.AddOptions<SecurityOptions>()
    .Bind(builder.Configuration.GetSection(SecurityOptions.Section))
    .Validate(o => o.ApiClients.All(c => !string.IsNullOrWhiteSpace(c.Name) && ApiKeyMiddleware.IsValidKeyHash(c.KeyHash)),
        "Security:ApiClients : chaque entrée doit avoir un Name et un KeyHash SHA-256 (64 caractères hexadécimaux).")
    .Validate(o => o.MaxFailuresPerUser > 0 && o.FailureWindowMinutes > 0 && o.RequestsPerClientPerMinute > 0,
        "Security : les limites doivent être strictement positives.")
    .ValidateOnStart();

// --- Services ------------------------------------------------------------
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<LoginAttemptTracker>();
if (OperatingSystem.IsWindows())
    builder.Services.AddSingleton<IAdAuthenticator, WindowsAdAuthenticator>();
else
    builder.Services.AddSingleton<IAdAuthenticator, LdapAdAuthenticator>();

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = (ctx, token) => new ValueTask(ctx.HttpContext.Response.WriteAsJsonAsync(new
    {
        success = false,
        error = "too_many_requests",
        message = "Trop de requêtes pour cette application. Réessayez dans une minute.",
    }, token));

    // Limite par application appelante (identifiée par sa clé d'API), à défaut par IP.
    options.AddPolicy(RateLimitPolicies.PerClient, ctx =>
    {
        var limit = ctx.RequestServices.GetRequiredService<IOptionsMonitor<SecurityOptions>>().CurrentValue.RequestsPerClientPerMinute;
        var client = ctx.Items[ApiKeyMiddleware.ClientItemKey] as string;
        var partition = client is null or ApiKeyMiddleware.AnonymousClient
            ? "ip:" + ctx.Connection.RemoteIpAddress
            : "client:" + client;
        return RateLimitPartition.GetFixedWindowLimiter(partition, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = limit,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        });
    });
});

builder.Services.AddControllers().ConfigureApiBehaviorOptions(options =>
{
    // Même format de réponse que le reste de l'API pour les requêtes mal formées.
    options.InvalidModelStateResponseFactory = _ => new BadRequestObjectResult(new
    {
        success = false,
        error = "invalid_request",
        message = "Nom d'utilisateur ou mot de passe invalide.",
    });
});

// --- Pipeline ------------------------------------------------------------
var app = builder.Build();

var security = app.Services.GetRequiredService<IOptions<SecurityOptions>>().Value;
var ldap = app.Services.GetRequiredService<IOptions<LdapOptions>>().Value;
if (security.ApiClients.Count == 0)
    app.Logger.LogWarning("Aucune application déclarée dans Security:ApiClients : le microservice accepte tous les appelants.");
if (!OperatingSystem.IsWindows() && !ldap.UseSsl)
    app.Logger.LogWarning("Ldap:UseSsl est désactivé : les mots de passe circulent en clair vers le contrôleur de domaine.");

app.UseExceptionHandler(errorApp => errorApp.Run(async ctx =>
{
    ctx.Response.StatusCode = StatusCodes.Status500InternalServerError;
    await ctx.Response.WriteAsJsonAsync(new { success = false, error = "internal_error", message = "Erreur interne." });
}));

app.Use(async (ctx, next) =>
{
    ctx.Response.Headers.XContentTypeOptions = "nosniff";
    ctx.Response.Headers.CacheControl = "no-store";

    if (security.RequireHttps && !ctx.Request.IsHttps)
    {
        ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
        await ctx.Response.WriteAsJsonAsync(new { success = false, error = "https_required", message = "HTTPS obligatoire." });
        return;
    }
    await next(ctx);
});

app.UseMiddleware<ApiKeyMiddleware>();
app.UseRateLimiter();
app.MapControllers();
app.Run();
