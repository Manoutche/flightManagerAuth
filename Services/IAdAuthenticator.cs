namespace FlightManagerApp.Services
{
    public enum AuthStatus
    {
        Success,
        InvalidCredentials,
        AccountLocked,
        AccountDisabled,
        PasswordExpired,
        Unavailable,
    }

    public sealed record AdUser(string Username, string? DisplayName, string? Email, IReadOnlyList<string> Groups);

    public sealed record AuthResult(AuthStatus Status, AdUser? User = null)
    {
        public static AuthResult Of(AuthStatus status) => new(status);
    }

    public interface IAdAuthenticator
    {
        /// <param name="username">sAMAccountName déjà validé et normalisé.</param>
        Task<AuthResult> AuthenticateAsync(string username, string password, CancellationToken cancellationToken);
    }
}
