using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Owin.Testing;
using Newtonsoft.Json;
using WebApiJwtAuthorization.Models;
using WebApiJwtAuthorization.Tests.Common;
using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace WebApiJwtAuthorization.Tests
{
    public class SimpleWebApiTestsStartup : Startup
    {
        protected override void CustomServiceConfiguration(ServiceCollection services)
        {
            services.AddSingleton<ITestStore>(new TestStore(new Dictionary<string, string>() { { "stuff", "test" } }));
        }
    }

    public class WebApiTests : WebApiTestBase<SimpleWebApiTestsStartup>
    {
        public WebApiTests(ITestOutputHelper output) : base(output)
        {
        }

        [Fact]
        public async void GetDependencyInjectionTest()
        {
            Output.WriteLine("Stuff happned");
            Trace.WriteLine("Trace stuff");

            var response = await TestHttpClient.GetAsync("http://testserver/api/simpleopen");
            Assert.True(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            
            Assert.Contains("test", result);
        }
    }
}