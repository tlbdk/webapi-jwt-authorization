﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;

namespace WebApiJwtAuthorization.Controllers
{
    public class DefaultController : ApiController
    {
        [HttpGet]
        [Route("api/simpleopen")]
        public IHttpActionResult SimpleOpen()
        {
           return Ok(new { stuff = "more stuff" });
        }

        [HttpGet]
        [Route("api/simpleauth")]
        [Authorize]
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
        [Route("api/roles")]
        [Authorize(Roles = "AuthLevel:1")]
        public IHttpActionResult Roles()
        {
            var identity = User.Identity as ClaimsIdentity;
            return Ok(identity.Claims.Select(c => new
            {
                Type = c.Type,
                Value = c.Value
            }));
        }
    }
}
