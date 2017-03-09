using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApiJwtAuthorization.Models
{
    public class TestStore : ITestStore
    {
        private readonly Dictionary<string, string> _dictionary;

        public TestStore(Dictionary<string, string> dictionary)
        {
            _dictionary = dictionary;
        }

        public string GetValue(string key)
        {
            string value;
            return _dictionary.TryGetValue(key, out value) ? value : null;
        }
    }
}