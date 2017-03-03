using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;

namespace WebApiJwtAuthorization
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            var config = new HttpConfiguration();
            config.MapHttpAttributeRoutes();
            ConfigureOAuth(app);
            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
            app.UseWebApi(config);
            
        }

        public void ConfigureOAuth(IAppBuilder app)
        {
            var issuer = "auth";
            var audience = "test";

            // jwt.io sample public key
            const string publicKeyBase64 = "MIIBnzCCAQgCCQDaXbZrtjRtfTANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwHhcNMTcwMzAyMTUxODI0WhcNMjcwMjI4MTUxODI0WjAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAN2Vq1GNGOiCjdaiOAYcUdgu6B1RYBj2JHd/LhqtY0DUqhLyRXDfdwmJtevxu/BQBSlqsLCW91sfp28Q5+i7T+AIVCwdR9CtIO/4y5JQwB7yPMoTipb6Mr7FBT1rTcZScoeSSV75DSlf+DqNdnuvX/EArkOjaRD5fnEr1yKlGAQrAgMBAAEwDQYJKoZIhvcNAQELBQADgYEA05V5SHw0kWlFDwVHSkAAAnizpvi671Zku+RK5jtTPp/o9HXB/zG02K1r8uI5THuhdqZx1d7j9T4+lTex0Ri6yhDMPD8tzEWFMyLOGpgErgjXidIY/TymOoG44LmDBsBW4u/XMUdEHBIyEeQDfeImYkkFeY0nLTNhC+7Uu4MwS9w=";
            var certificate = new X509Certificate2(Convert.FromBase64String(publicKeyBase64));

            // Api controllers with an [Authorize] attribute will be validated with JWT
            app.UseJwtBearerAuthentication(
                new JwtBearerAuthenticationOptions
                {
                    AuthenticationMode = AuthenticationMode.Active,
                    AllowedAudiences = new[] { audience },
                    IssuerSecurityTokenProviders = new IIssuerSecurityTokenProvider[]
                    {
                        new X509CertificateSecurityTokenProvider(issuer, certificate),
                    },
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        IssuerSigningKeyResolver = (a, b, c, d) => {
                            return new X509SecurityKey(certificate);
                        },
                        ValidAudience = audience,
                        ValidateAudience = true,
                        ValidIssuer = issuer,
                        ValidateIssuer = true,
                        ValidateLifetime = true,
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
                            // Create role for auth level
                            var authLevel = context.Ticket.Identity.Claims
                                .Where(c => c.Type == "http://schemas.microsoft.com/claims/authnclassreference")
                                .SingleOrDefault()?.Value;

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
                            
                            context.Ticket.Identity.AddClaim(new Claim("newCustomClaim", "newValue"));
                            return Task.FromResult<object>(null);
                        }   
                    }
                }
            );
        }
    }
}