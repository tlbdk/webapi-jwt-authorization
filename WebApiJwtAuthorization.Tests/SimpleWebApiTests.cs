using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Testing;
using Newtonsoft.Json;
using WebApiJwtAuthorization.Tests.Common;
using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace WebApiJwtAuthorization.Tests
{

    public class SimpleWebApiTests : IDisposable
    {
        private readonly TestServer _testServer;
        private readonly HttpClient _httpClient;
        private readonly JwtSigner _jwtSigner;

        private const string PrivatePfxCertificate = "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";

        private readonly ITestOutputHelper _output;

        public SimpleWebApiTests(ITestOutputHelper output)
        {
            _testServer = TestServer.Create<TestStartup>();
            _httpClient = new HttpClient(_testServer.Handler);
            _jwtSigner = new JwtSigner(PrivatePfxCertificate, "qwerty1234");

            this._output = output;
            Trace.Listeners.Add(new XunitTraceListener(output));
        }

        [Fact]
        public async void SimpleGetTest()
        {
            _output.WriteLine("Stuff happned");
            Trace.WriteLine("Trace stuff");

            var response = await _httpClient.GetAsync("http://testserver/api/simpleopen");
            Assert.True(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            
            Assert.Contains("stuff", result);
            
        }

        [Fact]
        public async void SimpleGetAuthTest()
        {
            var unixTimeNow = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var token = _jwtSigner.Sign(new
            {
                jit = "1234",
                iss = "auth",
                aud = "test",
                sid = "123456789",
                sub = "qwerty1234@customer.myorg.com",
                iat = unixTimeNow,
                exp = unixTimeNow + 600,
                acr = "1",
                amr = new List<string> {"password", "devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/simpleauth");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await _httpClient.SendAsync(httpRequestMessage);
            Assert.True(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("qwerty1234@customer.myorg.com", result);
        }

        [Fact]
        public async void SimpleGetTokenExpiredTest()
        {
            var unixTimeNow = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var token = _jwtSigner.Sign(new
            {
                jit = "1234",
                iss = "auth",
                aud = "test",
                sid = "123456789",
                sub = "qwerty1234@customer.myorg.com",
                iat = unixTimeNow - 600,
                exp = unixTimeNow - 500,
                acr = "1",
                amr = new List<string> {"password", "devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/simpleauth");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await _httpClient.SendAsync(httpRequestMessage);
            Assert.False(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("Authorization has been denied for this request", result);
        }

        [Fact]
        public async void SimpleGetTokenIssuedInTheFutureTest()
        {
            var unixTimeNow = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var token = _jwtSigner.Sign(new
            {
                jit = "1234",
                iss = "auth",
                aud = "test",
                sid = "123456789",
                sub = "qwerty1234@customer.myorg.com",
                //nbf = unixTimeNow + 600,
                iat = unixTimeNow + 600,
                exp = unixTimeNow + 1200,
                acr = "1",
                amr = new List<string> {"password", "devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/simpleauth");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await _httpClient.SendAsync(httpRequestMessage);
            Assert.False(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("Authorization has been denied for this request", result);
        }

        [Fact]
        public async void SimpleGetTokenNotBeforeInTheFutureTest()
        {
            var unixTimeNow = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var token = _jwtSigner.Sign(new
            {
                jit = "1234",
                iss = "auth",
                aud = "test",
                sid = "123456789",
                sub = "qwerty1234@customer.myorg.com",
                nbf = unixTimeNow + 600,
                iat = unixTimeNow,
                exp = unixTimeNow + 1200,
                acr = "1",
                amr = new List<string> {"password", "devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/simpleauth");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await _httpClient.SendAsync(httpRequestMessage);
            Assert.False(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("Authorization has been denied for this request", result);
        }


        [Fact]
        public async void SimpleGetTokenWrongAudienceTest()
        {
            var unixTimeNow = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var token = _jwtSigner.Sign(new
            {
                jit = "1234",
                iss = "auth",
                aud = "wrong",
                sid = "123456789",
                sub = "qwerty1234@customer.myorg.com",
                iat = unixTimeNow,
                exp = unixTimeNow + 600,
                acr = "1",
                amr = new List<string> {"password", "devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/simpleauth");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await _httpClient.SendAsync(httpRequestMessage);
            Assert.False(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("Authorization has been denied for this request", result);
        }

         [Fact]
        public async void SimpleGetTokenWrongIssuerTest()
        {
            var unixTimeNow = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var token = _jwtSigner.Sign(new
            {
                jit = "1234",
                iss = "wrong",
                aud = "test",
                sid = "123456789",
                sub = "qwerty1234@customer.myorg.com",
                iat = unixTimeNow,
                exp = unixTimeNow + 600,
                acr = "1",
                amr = new List<string> {"password", "devicetoken:1234"}
            });

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://testserver/api/simpleauth");
            httpRequestMessage.Headers.Add("Authorization", "Bearer " + token);
            var response = await _httpClient.SendAsync(httpRequestMessage);
            Assert.False(response.IsSuccessStatusCode);

            var result = await response.Content.ReadAsStringAsync();
            Assert.Contains("Authorization has been denied for this request", result);
        }

        public void Dispose()
        {
            _testServer.Dispose();
        }

        public class XunitTraceListener : TraceListener
        {
            private readonly ITestOutputHelper output;

            public XunitTraceListener(ITestOutputHelper output)
            {
                this.output = output;
            }

            public override void WriteLine(string str)
            {
                output.WriteLine(str);
            }

            public override void Write(string str)
            {
                output.WriteLine(str);
            }
        }
    }
}