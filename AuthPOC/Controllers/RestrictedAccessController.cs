using Microsoft.AspNetCore.Mvc;

namespace AuthPOC.Controllers
{
    [ApiController]
    [ServiceFilter(typeof(BasicAuthentication))]
    public class RestrictedAccessController : ControllerBase
    {
        private readonly IAuthorizationJWT _auth;

        public RestrictedAccessController(IAuthorizationJWT auth)
        {
            this._auth = auth;
        }

        [HttpGet("api/restrictedEndPoint")]
        public IActionResult GetRestrictedItem()
        {
            // Add restricted endpoint Get logic here

            return Ok("You are authorized, here is your secret data: ABC. Don't give this to anyone!");
        }

        [HttpPost("api/restrictedEndPoint")]
        public IActionResult PostRestrictedItem()
        {

            // Add restricted endpoint Post logic here

            return Ok("Post is authorized. Thank you.");
        }

        [HttpPost("api/refreshToken")]
        public IActionResult PostRefreshToken()
        {

            if (!this.HttpContext.Request.Headers.ContainsKey("Authorization"))
                return Unauthorized("Missing token");
            else
            {
                string result = _auth.RefreshToken(this.HttpContext.Request.Headers["Authorization"].ToString());
                return Ok(result);
            }
        }

    }
}
