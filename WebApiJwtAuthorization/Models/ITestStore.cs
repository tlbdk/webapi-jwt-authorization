using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApiJwtAuthorization.Models
{
    public interface ITestStore
    {
        string GetValue(string key);
    }
}