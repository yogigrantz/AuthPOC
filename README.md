# AuthPOC

This is a Proof of Concept C# .net 8 WebAPI application to Authenticate, Authorize, and Refresh JWT Token with these libaries only: 

  using Microsoft.IdentityModel.Tokens;  
  using System.IdentityModel.Tokens.Jwt;  
  using System.Security.Claims;  
  using System.Security.Cryptography;  
  using System.Security.Principal;  

It has 5 endpoints:

/api/Login - Get -> Open to public  
/api/Login - Post -> Open to public, requires username and password json payload, issue Bearer token upon authentication  
/api/restrictedEndPoint - Get -> Requires valid Bearer token jwt  
/api/restrictedEndPoint - Post -> Requires valid Bearer token jwt  
/api/refreshToken - Post ->  Requires valid Bearer token jwt  

This app will run out of the box provided the local machine is setup to debug in ssl. 

To run the application:
1. run it in the latest VS 22022 
2. Run a postman to post to https://localhost:7026/api/login with this json payload in the body. Please make sure that the input format selector is set to json, not text:

{
  "username": "tester",
  "password": "123"
}

3. Upon successful login, the api/login will output jwt
4. Use that jwt in the header with name Authorization, value: Bearer <jwt>, and post it to https://localhost:7026/api/restrictedEndpoint with either get or post method
5. To refresh jwt, post the jwt to https://localhost:7026/api/refreshToken, and then use that in the Authorization header for subsequent requests

