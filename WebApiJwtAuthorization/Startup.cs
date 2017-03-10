using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Web.Http;
using System.Web.Http.Tracing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Owin.Cors;
using Microsoft.Owin.Logging;
using Owin;
using WebApiJwtAuthorization.Common;
using WebApiJwtAuthorization.Models;

namespace WebApiJwtAuthorization
{
    public class Startup
    {
        public X509Certificate2 PublicKeyCertificate { get; set; } = new X509Certificate2(Convert.FromBase64String("MIIBnzCCAQgCCQDaXbZrtjRtfTANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwHhcNMTcwMzAyMTUxODI0WhcNMjcwMjI4MTUxODI0WjAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAN2Vq1GNGOiCjdaiOAYcUdgu6B1RYBj2JHd/LhqtY0DUqhLyRXDfdwmJtevxu/BQBSlqsLCW91sfp28Q5+i7T+AIVCwdR9CtIO/4y5JQwB7yPMoTipb6Mr7FBT1rTcZScoeSSV75DSlf+DqNdnuvX/EArkOjaRD5fnEr1yKlGAQrAgMBAAEwDQYJKoZIhvcNAQELBQADgYEA05V5SHw0kWlFDwVHSkAAAnizpvi671Zku+RK5jtTPp/o9HXB/zG02K1r8uI5THuhdqZx1d7j9T4+lTex0Ri6yhDMPD8tzEWFMyLOGpgErgjXidIY/TymOoG44LmDBsBW4u/XMUdEHBIyEeQDfeImYkkFeY0nLTNhC+7Uu4MwS9w="));
        public string[] Issuers { get; set; } = {"auth", "auth2"};
        public string[] Audiences { get; set; } = {"test", "test2"};

        public void Configuration(IAppBuilder app)
        {
            // Add custom trace logging to OWIN pipeline
            app.SetLoggerFactory(new TraceLoggerFactory());

            app.UseCors(CorsOptions.AllowAll);

            // Add custom jwt validation to OWIN pipeline
            app.UseCustomJwtAuthentication(PublicKeyCertificate, Issuers, Audiences);

            // Setup Dependency injection
            var services = new ServiceCollection();

            // Add all ApiControllers in this assembly
            var types = typeof(Startup).Assembly.GetExportedTypes().Where(t =>
                    typeof(ApiController).IsAssignableFrom(t)
                            && !t.IsAbstract
                            && !t.IsGenericTypeDefinition
                            && t.Name.EndsWith("Controller", StringComparison.Ordinal));
            foreach (var type in types)
            {
                services.AddTransient(type);
            }

            // Manually add a controller
            //services.AddTransient<TestController>();

            // Add services need for controllers
            services.AddSingleton<ITestStore>(new TestStore(new Dictionary<string, string>() { { "stuff", "production" } }));
            
            // Make overwriteable configuration for testing
            CustomServiceConfiguration(services);

            var config = new HttpConfiguration
            {
                DependencyResolver = new DefaultDependencyResolver(services.BuildServiceProvider()),
            };

            // WebApi logging
            var traceWriter = config.EnableSystemDiagnosticsTracing();
            traceWriter.IsVerbose = true;
            traceWriter.MinimumLevel = TraceLevel.Debug;

            // Use attibute based routing
            config.MapHttpAttributeRoutes();

            // Make overwriteable configuration for testing
            CustomHttpConfiguration(config);

            // Enable WebAPI support
            app.UseWebApi(config);
        }

        protected virtual void CustomHttpConfiguration(HttpConfiguration httpConfiguration)
        {

        }

        protected virtual void CustomServiceConfiguration(ServiceCollection services)
        {
           
        }

    }
}