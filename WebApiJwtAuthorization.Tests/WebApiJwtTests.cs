using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using WebApiJwtAuthorization.Tests.Common;
using Xunit;
using Xunit.Abstractions;

namespace WebApiJwtAuthorization.Tests
{
    public class WebApiJwtTestsStartup : Startup
    {
        protected override void CustomServiceConfiguration(ServiceCollection services)
        {
            services.AddTransient<TestController>();
        }
    }

    public class WebApiJwtTests : WebApiTestBase<WebApiJwtTestsStartup>
    {
        public WebApiJwtTests(ITestOutputHelper output) : base(output)
        {
        }

        [Fact]
        public async void AuthTest()
        {
            var unixTimeNow = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var token = JwtSigner.Sign(new
            {
                jit = "1234",
                iss = "auth",
                aud = "test",
                sid = "123456789",
                sub = "qwerty1234@customer.myorg.com",
                nbf = unixTimeNow - 600,
                iat = unixTimeNow,
                exp = unixTimeNow + 600,
                acr = "AM1",
                amr = new List<string> {"password", "devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/simpleauth");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.True(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("qwerty1234@customer.myorg.com", result);
        }

        [Fact]
        public async void AuthUsernameTest()
        {
            var unixTimeNow = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var token = JwtSigner.Sign(new
            {
                jit = "1234",
                iss = "auth",
                aud = "test",
                sid = "123456789",
                sub = "qwerty1234@customer.myorg.com",
                nbf = unixTimeNow - 600,
                iat = unixTimeNow,
                exp = unixTimeNow + 600,
                acr = "AM1",
                amr = new List<string> {"password", "devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/username");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.True(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("qwerty1234@customer.myorg.com", result);
        }

        [Fact]
        public async void TokenExpiredTest()
        {
            var unixTimeNow = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var token = JwtSigner.Sign(new
            {
                jit = "1234",
                iss = "auth",
                aud = "test",
                sid = "123456789",
                sub = "qwerty1234@customer.myorg.com",
                nbf = unixTimeNow - 600,
                iat = unixTimeNow - 600,
                exp = unixTimeNow - 500,
                acr = "AM1",
                amr = new List<string> {"password", "devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/simpleauth");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.False(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("Authorization has been denied for this request", result);
        }

        [Fact]
        public async void TokenIssuedInTheFutureTest()
        {
            var unixTimeNow = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var token = JwtSigner.Sign(new
            {
                jit = "1234",
                iss = "auth",
                aud = "test",
                sid = "123456789",
                sub = "qwerty1234@customer.myorg.com",
                nbf = unixTimeNow - 600,
                iat = unixTimeNow + 600,
                exp = unixTimeNow + 1200,
                acr = "AM1",
                amr = new List<string> {"password", "devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/simpleauth");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.False(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("Authorization has been denied for this request", result);
        }

        [Fact]
        public async void TokenNotBeforeInTheFutureTest()
        {
            var unixTimeNow = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var token = JwtSigner.Sign(new
            {
                jit = "1234",
                iss = "auth",
                aud = "test",
                sid = "123456789",
                sub = "qwerty1234@customer.myorg.com",
                nbf = unixTimeNow + 600,
                iat = unixTimeNow,
                exp = unixTimeNow + 1200,
                acr = "AM1",
                amr = new List<string> {"password", "devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/simpleauth");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.False(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("Authorization has been denied for this request", result);
        }


        [Fact]
        public async void TokenWrongAudienceTest()
        {
            var unixTimeNow = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var token = JwtSigner.Sign(new
            {
                jit = "1234",
                iss = "auth",
                aud = "wrong",
                sid = "123456789",
                sub = "qwerty1234@customer.myorg.com",
                nbf = unixTimeNow - 600,
                iat = unixTimeNow,
                exp = unixTimeNow + 600,
                acr = "AM1",
                amr = new List<string> {"password", "devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/simpleauth");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.False(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("Authorization has been denied for this request", result);
        }

        [Fact]
        public async void TokenWrongIssuerTest()
        {
            var unixTimeNow = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var token = JwtSigner.Sign(new
            {
                jit = "1234",
                iss = "wrong",
                aud = "test",
                sid = "123456789",
                sub = "qwerty1234@customer.myorg.com",
                nbf = unixTimeNow - 600,
                iat = unixTimeNow,
                exp = unixTimeNow + 600,
                acr = "AM1",
                amr = new List<string> {"password", "devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/simpleauth");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.False(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("Authorization has been denied for this request", result);
        }

        [Fact]
        public async void GetTokenAlgoNone()
        {
            var unixTimeNow = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var token = JwtSigner.Sign(
                new
                {
                  typ = "JWT",
                  alg = "none"
                },    
                new
                {
                    jit = "1234",
                    iss = "wrong",
                    aud = "test",
                    sid = "123456789",
                    sub = "qwerty1234@customer.myorg.com",
                    nbf = unixTimeNow - 600,
                    iat = unixTimeNow,
                    exp = unixTimeNow + 600,
                    acr = "AM1",
                    amr = new List<string> {"password", "devicetoken:1234"}
                }
            );

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/simpleauth");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.False(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("Authorization has been denied for this request", result);
        }

        [Fact]
        public async void GetTokenAlgoHs256()
        {
            var unixTimeNow = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var token = JwtSigner.Sign(
                new
                {
                    typ = "JWT",
                    alg = "HS256"
                },    
                new
                {
                    jit = "1234",
                    iss = "wrong",
                    aud = "test",
                    sid = "123456789",
                    sub = "qwerty1234@customer.myorg.com",
                    nbf = unixTimeNow - 600,
                    iat = unixTimeNow,
                    exp = unixTimeNow + 600,
                    acr = "AM1",
                    amr = new List<string> {"password", "devicetoken:1234"}
                }
            );

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/simpleauth");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.False(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("Authorization has been denied for this request", result);
        }
    }
}
