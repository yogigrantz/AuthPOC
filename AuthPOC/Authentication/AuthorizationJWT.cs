using AuthPOC.DTOs;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;

namespace AuthPOC;

public class AuthorizationJWT : IAuthorizationJWT
{
    private SigningCredentials _signingCredentials;
    private readonly Dictionary<string, string> _userCreds;
    private string _claimType;
    private string _issuer;
    private string _audience;
    private readonly string[] _allowedClients;
    private int _expirationMinutes;

    public AuthorizationJWT(Dictionary<string, string> userCreds, string claimType, int expMinutes, string issuer, string audience, string[] allowedClients = null)
    {
        _userCreds = userCreds;
        _claimType = claimType;
        _issuer = issuer;
        _audience = audience;
        _allowedClients = allowedClients;
        _expirationMinutes = expMinutes;
        RsaSecurityKey key = new RsaSecurityKey(GenerateKey());
        _signingCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature);
    }

    private RSAParameters GenerateKey()
    {
        using (RSACryptoServiceProvider key = new RSACryptoServiceProvider(2048))
        {
            return key.ExportParameters(true);
        }
    }

    public bool ServerIsAuthorized(ActionExecutingContext filterContext)
    {
        if (_allowedClients == null)
            return true;

        bool serverIsAllowed = false;
        if (filterContext.HttpContext.Request.Headers["origin"].Count > 0)
        {
            string origin = filterContext.HttpContext.Request.Headers["origin"].ToString().ToLower();
            foreach (string sn in _allowedClients)
            {
                if (origin.Contains(sn.ToLower()))
                {
                    serverIsAllowed = true;
                    break;
                }
            }
        }
        return serverIsAllowed;
    }

    public string? Authenticate(LoginDTO user)
    {
        if (_userCreds.TryGetValue(user.Username, out string pwd) && pwd == user.Password)
        {
            return IssueToken(user);
        }
        else
            return null;
    }

    public Tuple<bool, string?> Authorize(string token1)
    {

        JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
        try
        {
            JwtSecurityToken token = (JwtSecurityToken)handler.ReadJwtToken(token1.Replace("Bearer ", "", StringComparison.OrdinalIgnoreCase));
            var claimUser = token.Claims.FirstOrDefault(x => x.Type == _claimType);
            var claimExpiration = token.Claims.FirstOrDefault(x => x.Type == "exp");

            if (claimUser != null)
            {
                if (_userCreds.TryGetValue(claimUser.Value, out string? p))
                {
                    if (claimExpiration != null)
                    {
                        DateTime expDate = DateTimeOffset.FromUnixTimeSeconds(long.Parse(claimExpiration.Value)).LocalDateTime;
                        if ((expDate - DateTime.Now).TotalMinutes > 0)
                            return new Tuple<bool, string?>(true, claimUser.Value);
                        else
                            return new Tuple<bool, string?>(false, $"Auth Expired at {expDate}");
                    }
                    else
                        return new Tuple<bool, string?>(false, "Auth Expiration is undefined");
                }
                else
                    return new Tuple<bool, string?>(false, null);
            }
            else
                return new Tuple<bool, string?>(false, null);
        }
        catch (Exception ex)
        {
            return new Tuple<bool, string?>(false, ex.Message);
        }
    }

    private string IssueToken(LoginDTO user)
    {
        DateTime currDate = DateTime.Now;

        JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

        ClaimsIdentity identity = new ClaimsIdentity(
            new GenericIdentity(user.Username, "TokenAuth"),
            new[] {new Claim(_claimType, user.Username)
            }
        );

        SecurityToken securityToken = CreateSecurityToken(handler, identity);
 
        return handler.WriteToken(securityToken);
    }

    private SecurityToken CreateSecurityToken(JwtSecurityTokenHandler handler, ClaimsIdentity identity)
    {
        DateTime currDate = DateTime.Now;

        SecurityToken securityToken = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = _audience,
            SigningCredentials = _signingCredentials,
            Subject = identity,
            Expires = currDate.AddMinutes(_expirationMinutes),
            NotBefore = currDate,
            IssuedAt = currDate
        });
        return securityToken;
    }

    public string RefreshToken(string currentjwt)
    {
        try
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken token = (JwtSecurityToken)handler.ReadJwtToken(currentjwt.Replace("Bearer ", "", StringComparison.OrdinalIgnoreCase));
            var claimUser = token.Claims.FirstOrDefault(x => x.Type == _claimType);
            var claimExpiration = token.Claims.FirstOrDefault(x => x.Type == "exp");
            
            if (claimUser != null)
            {
                if (claimExpiration != null)
                {
                    DateTime expDate = DateTimeOffset.FromUnixTimeSeconds(long.Parse(claimExpiration.Value)).LocalDateTime;
                    if ((expDate - DateTime.Now).TotalMinutes > 0)
                    {
                        ClaimsIdentity identity = new ClaimsIdentity(
                        new GenericIdentity(claimUser.Value, "TokenAuth"),
                        new[] {new Claim(_claimType, claimUser.Value)
                        });

                        SecurityToken securityToken = CreateSecurityToken(handler, identity);

                        return handler.WriteToken(securityToken);
                    }
                    else
                        return currentjwt.Replace("Bearer ","");
                }
                else
                    return "Auth Expiration is undefined";
            }
            else
                return "Invalid username";
        }
        catch (Exception ex)
        {
            return "Invalid token";
        }
    }

    public DateTime? GetTokenExpiry(string currentjwt)
    {
        try
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken token = (JwtSecurityToken)handler.ReadJwtToken(currentjwt.Replace("Bearer ", "", StringComparison.OrdinalIgnoreCase));
            var claimUser = token.Claims.FirstOrDefault(x => x.Type == _claimType);
            var claimExpiration = token.Claims.FirstOrDefault(x => x.Type == "exp");

            if (claimUser != null)
            {
                if (claimExpiration != null)
                {
                    DateTime expDate = DateTimeOffset.FromUnixTimeSeconds(long.Parse(claimExpiration.Value)).LocalDateTime;
                    return expDate;
                }
                else
                    return null;
            }
            else
                return null;
        }
        catch (Exception ex)
        {
            return null;
        }
    }

}



