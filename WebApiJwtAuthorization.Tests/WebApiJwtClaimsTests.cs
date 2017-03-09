using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using WebApiJwtAuthorization.Tests.Common;
using Xunit;
using Xunit.Abstractions;

namespace WebApiJwtAuthorization.Tests
{
    public class WebApiJwtClaimsTests : WebApiTestBase<Startup>
    {
        public WebApiJwtClaimsTests(ITestOutputHelper output) : base(output)
        {
        }

        [Fact]
        public async void AuthLevelTest()
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
                acr = "AM2",
                amr = new List<string> {"password", "devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/authlevel2");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.True(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("qwerty1234@customer.myorg.com", result);
        }

        [Fact]
        public async void AuthLevelToLowTest()
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

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/authlevel2");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.False(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("Authorization has been denied for this request", result);
        }

        [Fact]
        public async void AuthMethodTest()
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
                acr = "AM2",
                amr = new List<string> {"password", "devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/authpassword");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.True(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("qwerty1234@customer.myorg.com", result);
        }

        [Fact]
        public async void AuthMethodWrongTest()
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
                amr = new List<string> {"devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/authpassword");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.False(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("Authorization has been denied for this request", result);
        }

        [Fact]
        public async void AuthMethodDeviceTest()
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
                acr = "AM2",
                amr = new List<string> {"password", "devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/authdevice");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.True(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("qwerty1234@customer.myorg.com", result);
        }

        [Fact]
        public async void AuthMethodDeviceMissingTest()
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
                amr = new List<string> {"password"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/authdevice");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.False(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("Authorization has been denied for this request", result);
        }

        [Fact]
        public async void AudiencesTest()
        {
            var unixTimeNow = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var token = JwtSigner.Sign(new
            {
                jit = "1234",
                iss = "auth",
                aud = "test2",
                sid = "123456789",
                sub = "qwerty1234@customer.myorg.com",
                nbf = unixTimeNow - 600,
                iat = unixTimeNow,
                exp = unixTimeNow + 600,
                acr = "AM2",
                amr = new List<string> {"password", "devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/authaudienceauth2");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.True(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("qwerty1234@customer.myorg.com", result);
        }

        [Fact]
        public async void AudiencesWrongTest()
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
                amr = new List<string> {"password"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/authaudienceauth2");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.False(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("Authorization has been denied for this request", result);
        }

        [Fact]
        public async void IssuerTest()
        {
            var unixTimeNow = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var token = JwtSigner.Sign(new
            {
                jit = "1234",
                iss = "auth2",
                aud = "test",
                sid = "123456789",
                sub = "qwerty1234@customer.myorg.com",
                nbf = unixTimeNow - 600,
                iat = unixTimeNow,
                exp = unixTimeNow + 600,
                acr = "AM2",
                amr = new List<string> {"password", "devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/authissuertest2");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.True(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("qwerty1234@customer.myorg.com", result);
        }

        [Fact]
        public async void IssuerWrongTest()
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
                amr = new List<string> {"password"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/authissuertest2");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await TestHttpClient.SendAsync(httpRequestMessage);
            Assert.False(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("Authorization has been denied for this request", result);
        }
    }
}
