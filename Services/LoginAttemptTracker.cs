using FlightManagerApp.Options;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace FlightManagerApp.Services
{
    /// <summary>
    /// Compte les échecs par compte AD et bloque temporairement les nouvelles tentatives,
    /// pour éviter qu'une attaque ne fasse verrouiller les comptes dans AD.
    /// Le compteur est en mémoire : il est remis à zéro au recyclage du pool IIS.
    /// </summary>
    public sealed class LoginAttemptTracker
    {
        private readonly IMemoryCache _cache;
        private readonly IOptionsMonitor<SecurityOptions> _options;

        public LoginAttemptTracker(IMemoryCache cache, IOptionsMonitor<SecurityOptions> options)
        {
            _cache = cache;
            _options = options;
        }

        private static string Key(string username) => "login-failures:" + username.ToUpperInvariant();

        public bool IsBlocked(string username)
            => _cache.TryGetValue(Key(username), out Counter? counter)
               && counter!.Value >= _options.CurrentValue.MaxFailuresPerUser;

        public void RegisterFailure(string username)
        {
            var counter = _cache.GetOrCreate(Key(username), entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(_options.CurrentValue.FailureWindowMinutes);
                return new Counter();
            })!;
            Interlocked.Increment(ref counter.Value);
        }

        public void Reset(string username) => _cache.Remove(Key(username));

        private sealed class Counter
        {
            public int Value;
        }
    }
}
