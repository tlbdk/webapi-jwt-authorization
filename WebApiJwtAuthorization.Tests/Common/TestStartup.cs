using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Dispatcher;
using Owin;

namespace WebApiJwtAuthorization.Tests
{
    public class TestStartup
    {
        public void Configuration(IAppBuilder app)
        {
	        new Startup().Configuration(app, (builder, configuration) =>
	        {
	            configuration.Services.Replace(typeof(IAssembliesResolver), new TestWebApiResolver());
	        });
        }
    }
}
