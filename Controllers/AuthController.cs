using Microsoft.AspNetCore.Mvc;
using System.DirectoryServices.AccountManagement;

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
            bool isAuthenticated = AuthenticateUser(request.Domain, request.Username, request.Password);
            if (isAuthenticated)
            {
                return Ok(new { success = true, message = "Authentification réussie." });
            }
            return Unauthorized(new { success = false, message = "Échec de l'authentification." });
        }

        private bool AuthenticateUser(string domain, string username, string password)
        {
            try
            {
                using (var context = new PrincipalContext(ContextType.Domain, domain))
                {
                    return context.ValidateCredentials(username, password);
                }
            }
            catch
            {
                return false;
            }
        }
    }

    public class LoginRequest
    {
        public string Domain { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}
