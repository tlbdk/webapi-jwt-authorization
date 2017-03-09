using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace WebApiJwtAuthorization.Tests.Common
{
    public class JwtSigner
    {
        private readonly HashAlgorithm _sha256 = SHA256.Create();
        private readonly RSACryptoServiceProvider _rsaCryptoServiceProvider;

        private readonly object _header = new
        {
            alg = "RS256",
            typ = "JWT"
        };

        public JwtSigner(string base64PfxCertificate, string password)
        {
            var certificate = new X509Certificate2(Convert.FromBase64String(base64PfxCertificate), password, X509KeyStorageFlags.Exportable);
            _rsaCryptoServiceProvider = (RSACryptoServiceProvider)certificate.PrivateKey;

            // The default CSP is limited to SHA1 for signing, but it we round trip into a new provider then we can do what we want
            if (_rsaCryptoServiceProvider.CspKeyContainerInfo.ProviderName == "Microsoft Base Cryptographic Provider v1.0")
            {
                _rsaCryptoServiceProvider = new RSACryptoServiceProvider();
                _rsaCryptoServiceProvider.FromXmlString(certificate.PrivateKey.ToXmlString(true));    
            }
        }

        public string Sign(object body)
        {
            return Sign(_header, body);
        }

        public string Sign(object header, object body)
        {            
            var headerBodyString = JsonBase64UrlSafeSerialize(header) + "." + JsonBase64UrlSafeSerialize(body);
            var signBytes = _rsaCryptoServiceProvider.SignData(Encoding.UTF8.GetBytes(headerBodyString), _sha256);
            var jwtString = headerBodyString + "." + ToBase64UrlSafeString(signBytes);
            return jwtString;
        }

        private static string JsonBase64UrlSafeSerialize(object obj)
        {
            return ToBase64UrlSafeString(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(obj)));
        }

        private static string ToBase64UrlSafeString(byte[] bytes)
        {
            return Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }
    }
}
