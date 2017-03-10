using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;

namespace WebApiJwtAuthorization.Controllers
{
    public class NormalController : ApiController
    {
        [HttpGet]
        [Route("normal/ok")]
        public IHttpActionResult SimpleOpen()
        {
            return Ok(new { stuff = "ok" });
        }
    }
}