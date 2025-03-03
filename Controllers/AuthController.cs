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
        [HttpPost("login")]
        [Consumes("application/json")]
        public IActionResult Authenticate([FromBody] LoginRequest request)
        {
            string Domain = "mondomain.com";
            bool isAuthenticated = AuthenticateUser(Domain, request.Username, request.Password);
            if (isAuthenticated)
            {
                return Ok(new { success = true, message = "Authentification réussie." });
            }
            return Unauthorized(new { success = false, message = "Le mot de pass ou le username est incorrect! " });
        }

        private bool AuthenticateUser(string domain, string username, string password)
        {
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
                string ldapServer = "address IP"; // Remplace par ton serveur AD echo %LOGONSERVER%
                int ldapPort = 389; // 636 si SSL/TLS est activé

                // Console.WriteLine($"[Linux] Tentative d'authentification LDAP pour {username}@{domain} via {ldapServer}:{ldapPort}");
                string bindDn = $"{username}@{domain}";
                using (var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(ldapServer, ldapPort)))
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
        // public string Domain { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

}
