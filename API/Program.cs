using API.DataDBContext;
using API.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

var connectSctring = builder.Configuration.GetConnectionString("Default")
    ?? throw new InvalidOperationException("connectedString");

builder.Services.AddSwaggerGen();
builder.Services.AddDbContext<DataDBContext>(opt => 
{
    opt.UseSqlServer(connectSctring);
});
builder.Services.AddAuthorization();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options => {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = JWTOptions.ISSUER,
            ValidateAudience = true,
            ValidAudience = JWTOptions.AUDIENCE,
            ValidateLifetime = true,
            IssuerSigningKey = JWTOptions.GetSymmetricSecurityKey(),
            ValidateIssuerSigningKey = true,

        };
    });

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapGet("/login/{username}/{role}", async (string username, string role, DataDBContext context) =>
{
    // Проверяем существование пользователя в базе данных
    var user = await context.User
        .FirstOrDefaultAsync(u => u.Username == username && u.Role == role);

    if (user == null)
    {
        return Results.NotFound(new { message = "Пользователь не найден в базе данных" });
    }

    var claims = new List<Claim> 
    { 
        new Claim(ClaimTypes.Name, username),
        new Claim(ClaimTypes.Role, role)
    };
    var jwt = new JwtSecurityToken(
            issuer: JWTOptions.ISSUER,
            audience: JWTOptions.AUDIENCE,
            claims: claims,
            expires: DateTime.Now.Add(TimeSpan.FromMinutes(5)),
            signingCredentials: new SigningCredentials(JWTOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));

    return new JwtSecurityTokenHandler().WriteToken(jwt);
});

// Защищенный эндпоинт для администраторов
app.MapGet("/admin", [Authorize(Roles = "Admin")] () =>
{
    return Results.Ok(new { message = "Доступ разрешен для администраторов" });
});

// Защищенный эндпоинт для пользователей
app.MapGet("/user", [Authorize(Roles = "User,Admin")] () =>
{
    return Results.Ok(new { message = "Доступ разрешен для пользователей и администраторов" });
});

app.UseAuthentication();
app.UseAuthorization();

app.Run();
