using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace KeyCloakTryOut.WebApi {

  public class KeycloakRequirement : IAuthorizationRequirement {
    /// <summary>
    /// Initializes a new instance of the <see cref="KeycloakRequirement"/> class.
    /// </summary>
    /// <param name="policyName">Name of the policy.</param>
    public KeycloakRequirement(string policyName) {
      PolicyName = policyName;
    }

    /// <summary>
    /// Gets the name of the policy.
    /// </summary>
    /// <value>
    /// The name of the policy.
    /// </value>
    public string PolicyName { get; }
  }

  public class KeycloakAuthorizationOptions {
    /// <summary>
    /// Gets or sets the required aithentication scheme that holds the token.
    /// </summary>
    /// <value>
    /// The required scheme.
    /// </value>
    public string RequiredScheme { get; set; } = JwtBearerDefaults.AuthenticationScheme;

    /// <summary>
    /// Gets or sets the token endpoint.
    /// </summary>
    /// <value>
    /// The token endpoint.
    /// </value>
    public string TokenEndpoint { get; set; }

    /// <summary>
    /// Gets or sets the backchannel handler.
    /// </summary>
    /// <value>
    /// The backchannel handler.
    /// </value>
    public HttpMessageHandler BackchannelHandler { get; set; } = new HttpClientHandler();

    /// <summary>
    /// Gets or sets the audience.
    /// </summary>
    /// <value>
    /// The audience.
    /// </value>
    public string Audience { get; set; }
  }

  public class KeycloakAuthorizationHandler : AuthorizationHandler<KeycloakRequirement> {
    private readonly IOptions<KeycloakAuthorizationOptions> _options;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public KeycloakAuthorizationHandler(IOptions<KeycloakAuthorizationOptions> options, IHttpContextAccessor httpContextAccessor) {
      _options = options;
      _httpContextAccessor = httpContextAccessor;
    }

    /// <summary>
    /// Makes a decision if authorization is allowed based on a specific requirement.
    /// </summary>
    /// <param name="context">The authorization context.</param>
    /// <param name="requirement">The requirement to evaluate.</param>
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, KeycloakRequirement requirement) {
      var options = _options.Value;
      var httpContext = _httpContextAccessor.HttpContext;
      var auth = await httpContext.AuthenticateAsync(options.RequiredScheme);
      if (!auth.Succeeded) {
        context.Fail();
        return;
      }

      var data = new Dictionary<string, string> {
        { "grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket" },
        { "response_mode", "decision" },
        { "audience", options.Audience },
        { "permission", $"{requirement.PolicyName}" }
      };

      var client = new HttpClient(options.BackchannelHandler);
      var token = await httpContext.GetTokenAsync(options.RequiredScheme, "access_token");
      client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

      var response = await client.PostAsync(options.TokenEndpoint, new FormUrlEncodedContent(data));
      if (response.IsSuccessStatusCode) {
        context.Succeed(requirement);
        return;
      }

      context.Fail();
    }
  }
}
