using AuthPOC.DTOs;
using Microsoft.AspNetCore.Mvc;

namespace AuthPOC.Controllers;


[ApiController]
public class LoginController : ControllerBase
{
    private readonly IAuthorizationJWT _auth;

    public LoginController(IAuthorizationJWT auth)
    {
        this._auth = auth;
    }

    [HttpGet("api/Login")]
    public IActionResult GetLogin()
    {
        return Ok("Ready to log in");
    }

    [HttpPost("api/Login")]
    public async Task<IActionResult> PostLogin(LoginDTO user)
    {
        string? result = _auth.Authenticate(user);
        if (result != null)
            return Ok(result);
        else
            return Unauthorized($"{user.Username} is not authenticated. Incorrect username or password");
    }

}
