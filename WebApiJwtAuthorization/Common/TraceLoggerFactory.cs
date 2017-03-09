using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Web;
using Microsoft.Owin.Logging;

namespace WebApiJwtAuthorization
{
    public class TraceLoggerFactory : ILoggerFactory
    {
        public ILogger Create(string name)
        {
            return new TraceLogger(name);
        }
    }

    public class TraceLogger : ILogger
    {
        private readonly string _loggerName;

        public TraceLogger(string loggerName)
        {
            _loggerName = loggerName;
        }

        public bool WriteCore(TraceEventType eventType, int eventId, object state, Exception exception, Func<object, Exception, string> formatter)
        {
            var baseMessage = string.Format("{0} (1) | {2}, {3}: {4}", _loggerName, eventType, DateTimeOffset.Now, eventId, formatter(state, exception));
            Trace.WriteLine(baseMessage);
            return true;
        }
    }
}