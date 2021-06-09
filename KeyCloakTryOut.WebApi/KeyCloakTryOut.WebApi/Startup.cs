using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;
using Swashbuckle.AspNetCore.SwaggerUI;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyCloakTryOut.WebApi {
  public class Startup {
    public Startup(IConfiguration configuration) {
      Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    // This method gets called by the runtime. Use this method to add services to the container.
    public void ConfigureServices(IServiceCollection services) {

      var jwtOptions = Configuration.GetSection("OpenIdConnect").Get<OpenIdConnectOptions>();

      services.AddControllers();
      services.AddSwaggerGen(c => {
        c.SwaggerDoc("v1", new OpenApiInfo { Title = "KeyCloakTryOut.WebApi", Version = "v1" });

        c.AddSecurityDefinition("oauth2",
        new OpenApiSecurityScheme() {
          Type = SecuritySchemeType.OAuth2,
          Name = "Authorization",
          In = ParameterLocation.Header,
          Scheme = "Bearer",
          OpenIdConnectUrl = new Uri(jwtOptions.Authority),
          Flows = new OpenApiOAuthFlows() {
            AuthorizationCode = new OpenApiOAuthFlow() {
              AuthorizationUrl = new Uri(jwtOptions.AuthUrl),
              TokenUrl = new Uri(jwtOptions.TokenUrl),
              //Scopes = new Dictionary<string, string>() { { "Name", "email" } },
            }
          }
        });
        c.OperationFilter<SecurityRequirementsOperationFilter>();
      });

      services
        .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options => {
          options.Authority = jwtOptions.Authority;
          options.Audience = jwtOptions.ClientId;
          options.RequireHttpsMetadata = false;
          options.TokenValidationParameters.NameClaimType = "preferred_username";
          options.TokenValidationParameters.RoleClaimType = "role";
          options.TokenValidationParameters.ValidAudience = jwtOptions.ClientId;
        });

      services.AddTransient<IClaimsTransformation>(_ => new KeycloakRolesClaimsTransformation("role", jwtOptions.ClientId));

      services.AddAuthorization();
      services.AddHttpContextAccessor();
      services.AddSingleton<IAuthorizationHandler, KeycloakAuthorizationHandler>();
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env) {
      if (env.IsDevelopment()) {

        var jwtOptions = Configuration.GetSection("OpenIdConnect").Get<OpenIdConnectOptions>();

        app.UseDeveloperExceptionPage();
        app.UseSwagger();
        app.UseSwaggerUI(c => {
          c.SwaggerEndpoint("/swagger/v1/swagger.json", "KeyCloakTryOut.WebApi v1");
          c.OAuthConfigObject = new OAuthConfigObject() {
            ClientId = jwtOptions.ClientId,
            ClientSecret = jwtOptions.ApiKey,
            UsePkceWithAuthorizationCodeGrant = true,
          };
          c.ConfigObject.DisplayRequestDuration = true;
        });
      }

      app.UseRouting();
      app.UseCors();

      app.UseAuthentication();
      app.UseAuthorization();

      app.UseEndpoints(endpoints => {
        endpoints.MapControllers();
      });
    }
  }
}
