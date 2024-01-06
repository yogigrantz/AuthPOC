using AuthPOC.DTOs;
using Microsoft.AspNetCore.Mvc.Filters;

namespace AuthPOC;

public interface IAuthorizationJWT
{
    string? Authenticate(LoginDTO user);
    Tuple<bool, string?> Authorize(string token1);
    bool ServerIsAuthorized(ActionExecutingContext filterContext);
    string RefreshToken(string jwt);
    DateTime? GetTokenExpiry(string jwt);
}