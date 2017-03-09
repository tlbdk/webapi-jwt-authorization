using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using Owin;

namespace WebApiJwtAuthorization.Common
{
    public static partial class AppBuilderAuthExtensions
    {
        public static void UseCustomJwtAuthentication(this IAppBuilder app, X509Certificate2 certificate, string[] issuers, string[] audiences)
        {
            // Api controllers with an [Authorize] attribute will be validated with JWT
            app.UseJwtBearerAuthentication(
                new JwtBearerAuthenticationOptions
                {
                    AuthenticationMode = AuthenticationMode.Active,
                    AllowedAudiences = audiences,
                    IssuerSecurityTokenProviders = new IIssuerSecurityTokenProvider[]
                    {
                        new X509CertificateSecurityTokenProvider(issuers[0], certificate)
                    },
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        IssuerSigningKeyResolver = (a, b, c, d) => {
                            return new X509SecurityKey(certificate);
                        },
                        ValidAudiences = audiences,
                        ValidateAudience = true,
                        ValidIssuers = issuers,
                        ValidateIssuer = true,
                        ValidateLifetime = true
                    },
                    Provider = new OAuthBearerAuthenticationProvider
                    {
                        OnRequestToken = context =>
                        {
                            var token = context.Token;
                            return Task.FromResult<object>(null);
                        },
                        OnValidateIdentity = context =>
                        {
                            // Validate iat
                            var issuedAtString = context.Ticket.Identity.Claims.SingleOrDefault(c => c.Type == "iat")?.Value;
                            if (issuedAtString != null)
                            {
                                var issuedAtDateTime = UnixTimeStampToDateTime(Convert.ToUInt32(issuedAtString));
                                var nowScrew = DateTime.UtcNow.AddMinutes(5); // Add 5 minute screw in validation
                                if (nowScrew < issuedAtDateTime)
                                {
                                    context.SetError("iat set in the future");
                                }
                            }

                            // Create role for auth level
                            var authLevel = context.Ticket.Identity.Claims
                                .SingleOrDefault(c => c.Type == "http://schemas.microsoft.com/claims/authnclassreference")?.Value;

                            if (!string.IsNullOrEmpty(authLevel))
                            {
                                context.Ticket.Identity.AddClaim(new Claim(ClaimTypes.Role, "AuthLevel:" + authLevel) );
                            }

                            // Create roles for auth methods
                            var authMethods = context.Ticket.Identity.Claims
                                .Where(c => c.Type == "http://schemas.microsoft.com/claims/authnmethodsreferences")
                                .Select(c => c.Value);

                            foreach(var authMethod in authMethods)
                            {
                                context.Ticket.Identity.AddClaim(new Claim(ClaimTypes.Role, "AuthMethod:" + authMethod.Split(':')[0]));
                            }

                            return Task.FromResult<object>(null);
                        }
                    }
                }
            );
        }

        private static DateTime UnixTimeStampToDateTime(double unixTimeStamp)
        {
            // Unix timestamp is seconds past epoch
            var dateTime = new DateTime(1970, 1 , 1, 0 , 0, 0, 0, DateTimeKind.Utc);
            return dateTime.AddSeconds(unixTimeStamp);
        }
    }
}