using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Net;
using Microsoft.AspNetCore.Mvc;
using System.Runtime.InteropServices; // Pour détecter l'OS

namespace FlightManagerApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly string _ldapServer;
        private readonly string _ldapDomain;
        private readonly int _ldapPort;

        public AuthController()
        {
            _ldapServer = Environment.GetEnvironmentVariable("LDAP_SERVER") ?? "";
            _ldapDomain = Environment.GetEnvironmentVariable("LDAP_DOMAIN") ?? "";
            _ldapPort = 389; // 636 si SSL/TLS est activé
        }
        [HttpPost("login")]
        [Consumes("application/json")]
        public IActionResult Authenticate([FromBody] LoginRequest request)
        {
            bool isAuthenticated = AuthenticateUser(_ldapDomain, request.Username, request.Password);
            if (isAuthenticated)
            {
                return Ok(new { success = true, message = "Authentification réussie." });
            }
            return Unauthorized(new { success = false, message = "Le mot de pass ou le username est incorrect! " });
        }

        private bool AuthenticateUser(string domain, string username, string password)
        {
            if (username.Trim() == "" || password.Trim() == "")
            {
                Console.WriteLine($" Certainn");
                return false;
            }
            // try
            // {
            //     using (var context = new PrincipalContext(ContextType.Domain, domain))
            //     {
            //         return context.ValidateCredentials(username, password);
            //     }
            // }
            // catch(Exception ex)
            // {
            //     Console.WriteLine($"Erreur lors de l'authentification : {ex.Message}");
            //     return false;
            // }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return AuthenticateWithWindows(domain, username, password);
            }
            else
            {
                return AuthenticateWithLdap(domain, username, password);
            }
        }

        private bool  AuthenticateWithWindows(string domain, string username, string password){
        try
            {
                using (var context = new PrincipalContext(ContextType.Domain, domain))
                {
                    return context.ValidateCredentials(username, password);
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine($"Erreur lors de l'authentification : {ex.Message}");
                return false;
            }
        }

        private bool AuthenticateWithLdap(string domain, string username, string password)
        {
            try
            {
              
                // Console.WriteLine($"[Linux] Tentative d'authentification LDAP pour {username}@{domain} via {ldapServer}:{ldapPort}");
                string bindDn = $"{username}@{domain}";
                using (var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(_ldapServer, _ldapPort)))
                {
                    ldapConnection.AuthType = AuthType.Basic;
                    ldapConnection.SessionOptions.ProtocolVersion = 3;
                    ldapConnection.Credential = new NetworkCredential(bindDn, password);
                    ldapConnection.Bind(); // Teste la connexion

                    Console.WriteLine("[Linux] Authentification LDAP réussie !");
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Linux] ❌ Erreur LDAP : {ex.Message}");
                return false;
            }
        }
    
    }

    
    
    public class LoginRequest
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

}
