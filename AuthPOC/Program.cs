using AuthPOC;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
Dictionary<string, string> userCreds = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
userCreds.Add("tester", "123");
int jwtExpMinutes = 3; // jwt will expire in 3 minutes

builder.Services.AddSingleton<IAuthorizationJWT, AuthorizationJWT>(_ => new AuthorizationJWT(userCreds, "username", jwtExpMinutes, "Yogi Grantz", "General Audience"));
builder.Services.AddScoped<BasicAuthentication>();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseHttpsRedirection();

app.MapControllers();

app.UseSwagger();
app.UseSwaggerUI();

app.Run();
