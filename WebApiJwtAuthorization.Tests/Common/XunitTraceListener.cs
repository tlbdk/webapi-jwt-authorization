using System.Diagnostics;
using Xunit.Abstractions;

namespace WebApiJwtAuthorization.Tests.Common
{
    public class XunitTraceListener : TraceListener
    {
        private readonly ITestOutputHelper _output;

        public XunitTraceListener(ITestOutputHelper output)
        {
            _output = output;
        }

        public override void WriteLine(string str)
        {
            try
            {
                _output.WriteLine(str);
            }
            catch
            {
                // Ignored
            }
        }

        public override void Write(string str)
        {
            try
            {
                _output.WriteLine(str);
            }
            catch
            {
                // Ignored
            }
            
        }
    }

}