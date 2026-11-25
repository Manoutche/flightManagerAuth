namespace FlightManagerApp.Options
{
    /// <summary>Paramètres de sécurité du microservice (section "Security").</summary>
    public sealed class SecurityOptions
    {
        public const string Section = "Security";

        /// <summary>Refuse toute requête qui n'arrive pas en HTTPS (403).</summary>
        public bool RequireHttps { get; set; } = true;

        /// <summary>
        /// Applications autorisées à appeler le microservice. Si la liste est vide,
        /// aucune clé n'est exigée (mode de transition, un avertissement est journalisé).
        /// </summary>
        public List<ApiClient> ApiClients { get; set; } = new();

        /// <summary>Échecs tolérés par compte avant blocage temporaire. Doit rester sous le seuil de verrouillage AD.</summary>
        public int MaxFailuresPerUser { get; set; } = 5;

        /// <summary>Durée (minutes) de la fenêtre de comptage des échecs et du blocage.</summary>
        public int FailureWindowMinutes { get; set; } = 15;

        /// <summary>Requêtes max par minute et par application appelante.</summary>
        public int RequestsPerClientPerMinute { get; set; } = 120;
    }

    public sealed class ApiClient
    {
        /// <summary>Nom de l'application appelante (apparaît dans les journaux d'audit).</summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>Empreinte SHA-256 (hexadécimal, 64 caractères) de la clé d'API. La clé elle-même n'est jamais stockée.</summary>
        public string KeyHash { get; set; } = string.Empty;
    }
}
