using System.Linq;
using System.Security.Claims;
using System.Web.Http;
using WebApiJwtAuthorization.Common;
using WebApiJwtAuthorization.Models;

namespace WebApiJwtAuthorization.Tests
{
    public class TestController : ApiController
    {
        private readonly ITestStore _store;

        public TestController(ITestStore store)
        {
            _store = store;
        }

        [HttpGet]
        [Route("api/simpleopen")]
        public IHttpActionResult SimpleOpen()
        {
           return Ok(new { stuff = _store.GetValue("stuff") });
        }

        [HttpGet]
        [Route("api/simpleauth")]
        [JwtAuthorize(AuthenticationLevel = "AM1")]
        public IHttpActionResult SimpleAuth()
        {
            var identity = User.Identity as ClaimsIdentity;
            return Ok(identity?.Claims.Select(c => new
            {
                Type = c.Type,
                Value = c.Value
            }));
        }

        [HttpGet]
        [Route("api/username")]
        [JwtAuthorize(AuthenticationLevel = "AM1")]
        public IHttpActionResult SimpleAuthName()
        {
            var identity = User.Identity as ClaimsIdentity;
            return Ok(identity?.Name);
        }

        [HttpGet]
        [Route("api/authlevel2")]
        [JwtAuthorize(AuthenticationLevel = "AM2")]
        public IHttpActionResult Authlevel2()
        {
            var identity = User.Identity as ClaimsIdentity;
            return Ok(identity?.Claims.Select(c => new
            {
                Type = c.Type,
                Value = c.Value
            }));
        }

        [HttpGet]
        [Route("api/authpassword")]
        [JwtAuthorize(AuthenticationLevel = "AM1", AuthenticationMethods = "password")]
        public IHttpActionResult AuthMethodPassword()
        {
            var identity = User.Identity as ClaimsIdentity;
            return Ok(identity?.Claims.Select(c => new
            {
                Type = c.Type,
                Value = c.Value
            }));
        }

        [HttpGet]
        [Route("api/authdevice")]
        [JwtAuthorize(AuthenticationMethods = "devicetoken")]
        public IHttpActionResult AuthMethodDevice()
        {
            var identity = User.Identity as ClaimsIdentity;
            return Ok(identity?.Claims.Select(c => new
            {
                Type = c.Type,
                Value = c.Value
            }));
        }

        [HttpGet]
        [Route("api/authissuertest2")]
        [JwtAuthorize(Issuers = "auth2")]
        public IHttpActionResult IssuerTest2()
        {
            var identity = User.Identity as ClaimsIdentity;
            return Ok(identity?.Claims.Select(c => new
            {
                Type = c.Type,
                Value = c.Value
            }));
        }

        [HttpGet]
        [Route("api/authaudienceauth2")]
        [JwtAuthorize(Audiences = "test2")]
        public IHttpActionResult AudienceAuth2()
        {
            var identity = User.Identity as ClaimsIdentity;
            return Ok(identity?.Claims.Select(c => new
            {
                Type = c.Type,
                Value = c.Value
            }));
        }

    }
}
