using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Http.Controllers;

namespace WebApiJwtAuthorization.Common
{
    public class JwtAuthorizeAttribute : System.Web.Http.AuthorizeAttribute
    {
        private string[] _authenticationMethods = { };
        private string[] _audiences = { };
        private string[] _issuers = { };
        private readonly Regex _reAuthLevel = new Regex(@"^AM([1234])$");
        private short _authenticationLevel = -1;

        protected override bool IsAuthorized(HttpActionContext actionContext)
        {
            if (!base.IsAuthorized(actionContext)) return false;
            
            var claimsIdentity = actionContext.ControllerContext.RequestContext.Principal.Identity as ClaimsIdentity;
            if (claimsIdentity == null) return false;

            if (_audiences.Length > 0)
            {
                var requestAudiences = claimsIdentity.Claims
                    .Where(c => c.Type == "aud")
                    .Select(c => c.Value);

                if (!_audiences.Any(a => requestAudiences.Contains(a))) return false;
            }

            if (_issuers.Length > 0)
            {
                var requestIssuer = claimsIdentity.Claims.SingleOrDefault(c => c.Type == "iss")?.Value;
                if (requestIssuer == null) return false;

                if (!_issuers.Any(i => requestIssuer.Contains(i))) return false;
            }


            if (_authenticationMethods.Length > 0)
            {
                var requestAuthenticationMethods = claimsIdentity.Claims
                    .Where(c => c.Type == "http://schemas.microsoft.com/claims/authnmethodsreferences")
                    .Select(c => c.Value.Split(':')[0]);

                if (!_authenticationMethods.Any(am => requestAuthenticationMethods.Contains(am))) return false;
            }

            if (_authenticationLevel != -1)
            {
                var authLevel = claimsIdentity.Claims.SingleOrDefault(c => c.Type == "http://schemas.microsoft.com/claims/authnclassreference")?.Value;
                if (authLevel == null) return false;

                var match = _reAuthLevel.Match(authLevel);
                if (!match.Success) return false;

                short requestAuthenticationLevel = -1;
                if (!short.TryParse(match.Groups[1].Value, out requestAuthenticationLevel)) return false;
                
                if(_authenticationLevel > requestAuthenticationLevel) return false;
            }

            return true;
        }

        public string Audiences
        {
            get { return string.Join(", ", _audiences); }
            set { _audiences = value.Split(',').Select(p => p.Trim()).ToArray(); }
        }

        public string Issuers
        {
            get { return string.Join(", ", _issuers); }
            set { _issuers = value.Split(',').Select(p => p.Trim()).ToArray();; }
        }

        public string AuthenticationMethods
        {
            get { return string.Join(", ", _authenticationMethods); }
            set { _authenticationMethods = value.Split(',').Select(p => p.Trim()).ToArray();; }
        }

        public string AuthenticationLevel
        {
            get { return $"AM{_authenticationLevel}"; }
            set
            {
                short level = 0;
                var match = _reAuthLevel.Match(value);
                if (match.Success && short.TryParse(match.Groups[1].Value, out level))
                {
                    _authenticationLevel = level;
                }
                else
                {
                    throw new FormatException("AuthenticationLevel not in expected format: AM1, AM2, AM3 or AM4");
                }
            }
        }
    }
}