using System;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Tracing;
using Microsoft.Owin.Cors;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using Owin;

namespace WebApiJwtAuthorization
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            Configuration(app, null);
        }

        public void Configuration(IAppBuilder app, Action<IAppBuilder, HttpConfiguration> testingFunc)
        {
            app.SetLoggerFactory(new TraceLoggerFactory());

            var config = new HttpConfiguration();
            
            // WebApi logging
            /* var traceWriter = config.EnableSystemDiagnosticsTracing();
            traceWriter.IsVerbose = true;
            traceWriter.MinimumLevel = TraceLevel.Debug; */

            config.MapHttpAttributeRoutes();
            ConfigureOAuth(app);
            app.UseCors(CorsOptions.AllowAll);
            testingFunc?.Invoke(app, config);
            app.UseWebApi(config);            
        }

        private static void ConfigureOAuth(IAppBuilder app)
        {
            const string issuer = "auth";
            const string audience = "test";

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
                        new X509CertificateSecurityTokenProvider(issuer, certificate)
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