using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using System.Web;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json.Linq;
using Microsoft.Extensions.Options;

namespace swaggerex
{
    public class AuthAttribute : IActionFilter
    {
        public readonly AppSettings _appSettings;
        string publickey = null;
        string iss = null;
        string JWT_TYPE = null;
        string KEYFACTORY = null;
        string JWT_ALGORITHM = null;
        string sub = null;
        public AuthAttribute(IOptions<AppSettings> appSettingAccess) {
           
            _appSettings = appSettingAccess.Value;
            publickey = _appSettings.publicKey;//"apigateway-nonprod";
            iss = _appSettings.iss;
            JWT_TYPE = _appSettings.JWT_TYPE;
            KEYFACTORY = _appSettings.KEYFACTORY;
            JWT_ALGORITHM = _appSettings.JWT_ALGORITHM;
            sub=_appSettings.sub;
        }
       
        public void OnActionExecuted(ActionExecutedContext context)
        {
           // throw new NotImplementedException();
        }

        public void OnActionExecuting(ActionExecutingContext context)
        {

            // configure jwt authentication
            //var key = Encoding.ASCII.GetBytes(publickey);
             byte[] key = null;



            // byte[] publicBytes = Convert.FromBase64String(publickey);// Base64.getDecoder().decode(publickey.getBytes());
            // byte[] bytes = Encoding.ASCII.GetBytes(publickey);
            byte[] textAsBytes = System.Convert.FromBase64String(publickey);
            String headers = context.HttpContext.Request.Headers["Authorization"];
            if (headers == null)
            {
                throw new Exception("No Header Found in  JWT Request");
            }
            else
            {
                String jwtToken = headers.Substring(7);
                headers = jwtToken;
                string[] parts = headers.Split('.');
                string header = parts[0];
                string payload = parts[1];
                string headerJson = Encoding.UTF8.GetString(Base64UrlDecode(header));
                JObject headerData = JObject.Parse(headerJson);
                string payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));
                JObject payloadData = JObject.Parse(payloadJson);
                AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(textAsBytes);
                RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
                RSAParameters rsaParameters = new RSAParameters();
                rsaParameters.Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned();
                rsaParameters.Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned();
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(rsaParameters);
                SHA256 sha256 = SHA256.Create();
                byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(parts[0] + '.' + parts[1]));
                RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                rsaDeformatter.SetHashAlgorithm("SHA256");
                if (!rsaDeformatter.VerifySignature(hash, FromBase64Url(parts[2])))
                    throw new ApplicationException(string.Format("Invalid signature"));
                //Check for header and payload 
                Validate(headerData, payloadData);
            }
        }

        private bool Validate(JObject headerData, JObject payloadData)
        {
            if (headerData["typ"].ToString() != JWT_TYPE || headerData["alg"].ToString() != JWT_ALGORITHM)
            {
                throw new Exception("Invalid JWT Type or Algorithm");
            }
            if (!payloadData["sub"].ToString().Contains(sub) || payloadData["iss"].ToString() != iss)
            {
                throw new Exception("Invalid JWT Sub or Issuer");
            }
            return true;
        }
          
        static byte[] FromBase64Url(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/")
                .Replace("-", "+");
            return Convert.FromBase64String(base64);
        }

        // from JWT spec
        private  byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 1: output += "==="; break; // Three pad chars
                case 2: output += "=="; break; // Two pad chars
                case 3: output += "="; break; // One pad char
                default: throw new System.Exception("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }

    }
    }

