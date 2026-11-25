namespace FlightManagerApp.Options
{
    /// <summary>Paramètres de connexion à Active Directory (section "Ldap").</summary>
    public sealed class LdapOptions
    {
        public const string Section = "Ldap";

        /// <summary>Domaine AD, ex. "mondomaine.local". Obligatoire.</summary>
        public string Domain { get; set; } = string.Empty;

        /// <summary>
        /// Contrôleur de domaine. Facultatif sous Windows (le DC est trouvé via le domaine),
        /// obligatoire sur les autres OS.
        /// </summary>
        public string? Server { get; set; }

        /// <summary>Port LDAP utilisé hors Windows (636 = LDAPS).</summary>
        public int Port { get; set; } = 636;

        /// <summary>LDAPS hors Windows. Ne jamais désactiver en production : le mot de passe passerait en clair.</summary>
        public bool UseSsl { get; set; } = true;

        /// <summary>Délai max d'un appel à AD avant de répondre 503.</summary>
        public int TimeoutSeconds { get; set; } = 10;

        /// <summary>Renvoie nom affiché, e-mail et groupes AD directs après une authentification réussie.</summary>
        public bool IncludeUserDetails { get; set; } = true;
    }
}
