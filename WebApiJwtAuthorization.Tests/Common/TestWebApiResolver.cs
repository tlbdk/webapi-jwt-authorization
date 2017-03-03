using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http.Dispatcher;
using WebApiJwtAuthorization.Controllers;

namespace WebApiJwtAuthorization.Tests
{
    class TestWebApiResolver : DefaultAssembliesResolver
    {
        public override ICollection<Assembly> GetAssemblies()
        {
            return new List<Assembly> { typeof(DefaultController).Assembly };
        }
    }
}
