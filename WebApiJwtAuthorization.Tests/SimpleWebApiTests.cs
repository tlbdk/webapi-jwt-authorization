﻿using System;
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

        private const string PrivatePfxCertificate = "MIIFmQIBAzCCBV8GCSqGSIb3DQEHAaCCBVAEggVMMIIFSDCCAkcGCSqGSIb3DQEH\nBqCCAjgwggI0AgEAMIICLQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIPde5\nPASZVLoCAggAgIICAKgXfRkvjaCMAbV2WyMovu2vUXEgXS391SRDEm6bmianV0ZZ\n6Ymi+idg+wsnYCTSWYBzTLvjppMVbfWrpKgLQqhRQ1P1pOs7BdOIUYKBLK0ohn/g\nAScKUTGMuGNbXcl3catgIzTzUr+ZfP+4YvHyzSiI64VNNGsOqBWOZPaDEX8zjw4T\n4RAbUbl6+UPHtZUMEzeXXUVmY0GBccVoQ0ANTOCaLaPlxbwYb04XYblcifWHnHKB\nzckpjdoaT/BlLuNt1VyQprEnxjYI0SZ5+LBYNoUG/mQBjpfBZ2bXfBscuc4zZXQZ\nNGTgazwPHezDcFP1lL3DMN9Ltpffd7x8A81cZMVJutzTnZ8B8Qz+e0SiwzS+pFo4\nNhJvW/vS8rBRyNTK9M8WOr2G6YQGems2IcAnIxVBg3hxO+jm8dGeS2zp3+3LoEFA\ny2twrEbxN8Z3g6gDOWrnn4VVQXUzBQb/zY3K3Kiv4+2yyF2Jcyms3XP4r5ek3fmr\nf0iVFO9xQkyFetJ/i9ZP3WCXRsqQ/W2MkvsEaa0mjBTtBN7GXLlsgfClwaPEWJGo\nN14muUyDWALyC0UaJ4L4zE4rsB5UBumRWvatzYzC2hXpWYcH+4jVBvR/NmONH8aL\n1Ghf69kcl1Tx433BRYaFNjla1P6cQ6u+lUqFB2onrzUfGj1VncaH+To5scb5MIIC\n+QYJKoZIhvcNAQcBoIIC6gSCAuYwggLiMIIC3gYLKoZIhvcNAQwKAQKgggKmMIIC\nojAcBgoqhkiG9w0BDAEDMA4ECJpDXGYGRJLUAgIIAASCAoBM1psBn3L8ToRYopIi\nnzrURdjNpwavA2lLg+fAVLkwUvKVMGNvA/AH2bsr4YDt1/gy8Ky6sx2ibH0xM0Im\n++bEOl1T0zsW3qO2YbEzO6WHLAcWRYfTpzc7oNxmNxm6F3hgzwo3W7fTqajD0rbw\n7OLco6DyjNFXgftany4ehscHLdA5fIEGENAD0h2ZyjE4qnYElQraqypSUpIKhxVx\n0f6psaSYAzCMzZNf1WKW3eIl59kIgjMKdRQtOowzsbm/8k7pHhZWBiIkPxKMXhgO\nmQoOin+0IM7HEc3SBzks15YzGhx2ONiw9IRlD7JcoMfsQYhSPgAwWn1gDH6BVABx\nzZrOrviRL8Wv76+69P1EW5WkMn0+K58Ej4ZvNkVuD3fUXpy2oq0cNzYL9Z82kXxs\nBRY/YWpAwZItPBCzq1FKLLPF/EfzX6HeTFkv4QdDRflb5zO03e0Qqi+RXxp/LsKR\nUOnQwOFGs3amkQlWBesNfA5EgdaqpmW8iYloexpcBLK1qcdcGf/JDUxCRWy0M7Ya\necOzwmmciHNXWhn4uXfNDwGVI2hiJiI3E45++vDsdH07hA++zZxPHAdjWDYQvugD\nu4TURuu/DEb/YT6+WHOSQDbGVWS1AmJkVsxB+IXORd3DjVPlagCb/ggBwOIzZgtZ\nCZDaMaGOE4oKSN/47I0JmpxoPtaO5mm+jAjGreLYIHIQCa/xQwNX4S4vlHh0AhJE\nRoiISy0z1WykIuMm9i8NFZo9Ca/8qGCTLr5uA+71aX4y48RmRkdMjEYYAtQAFdqg\n92RmY5113SO6OFslRTtsAnIKYI6Xd3lyOUAmHA4Mm+vZp4Vv/w6YUrhYnaO73qHA\n5F/CMSUwIwYJKoZIhvcNAQkVMRYEFH9spf216+4KCRpx2XynLsB5mZznMDEwITAJ\nBgUrDgMCGgUABBRxVJkh/HI7q8nqY7C0sdbAvAgYPQQIksyowXWktR8CAggA";

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