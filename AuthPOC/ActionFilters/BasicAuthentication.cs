using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace AuthPOC;

// ----- This action filter class is for authenticating against existing user credentials in the server ------- 
public class BasicAuthentication : Attribute, IAsyncActionFilter
{
    private readonly IAuthorizationJWT _auth;

    public BasicAuthentication(IAuthorizationJWT auth)
    {
        this._auth = auth;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        ResultDTO resultDTO = new ResultDTO()
        {
            requestdatetime = DateTime.Now
        };

        try
        {
            if (!context.HttpContext.Request.Headers.ContainsKey("Authorization"))
            {
                context.HttpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
                resultDTO.status = "Missing Auth header";
                resultDTO.statuscode = -1;
                resultDTO.message = "Please include bearer token in your auth header";
                context.Result = new JsonResult(resultDTO);
                return;
            }
            else
            {
                var auth = _auth.Authorize(context.HttpContext.Request.Headers["Authorization"].ToString());
                if (!auth.Item1)
                {
                    context.HttpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    resultDTO.status = "Invalid Auth Header";
                    resultDTO.statuscode = -1;
                    resultDTO.message = $"{auth.Item2}";
                    context.Result = new JsonResult(resultDTO);
                    return;
                }
            }
        }
        catch (Exception ex)
        {
            context.HttpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;
            resultDTO.status = "Internal Error";
            resultDTO.statuscode = -1;
            resultDTO.message = ex.Message;
            context.Result = new JsonResult(resultDTO);
            return;
        }

        await next();
    }
}
