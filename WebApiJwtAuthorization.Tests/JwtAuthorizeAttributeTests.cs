using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using WebApiJwtAuthorization.Common;
using Xunit;

namespace WebApiJwtAuthorization.Tests
{
    public class JwtAuthorizeAttributeTests
    {
        [Fact]
        public void CorrectUsage()
        {
            var jwtAttribute = new JwtAuthorizeAttribute
            {
                AuthenticationLevel = "AM2",
                Audiences = "auth2, auth1",
                AuthenticationMethods = "password, device",
                Issuers = "issuer1, issuer2"
            };

            Assert.Equal(jwtAttribute.AuthenticationLevel, "AM2");
            Assert.Equal(jwtAttribute.Audiences, "auth2, auth1");
            Assert.Equal(jwtAttribute.AuthenticationMethods, "password, device");
            Assert.Equal(jwtAttribute.Issuers, "issuer1, issuer2");
        }

        [Fact]
        public void WrongAuthLevel()
        {
            Exception ex = Assert.Throws<FormatException>(() => new JwtAuthorizeAttribute
            {
                AuthenticationLevel = "2",
            });
            Assert.Equal("AuthenticationLevel not in expected format: AM1, AM2, AM3 or AM4", ex.Message);
        }
    }
}
