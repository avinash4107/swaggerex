using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace swaggerex
{
    public class AppSettings
    {
        public  string publicKey { get; set; }
        public string iss { get; set; }
        public string JWT_ALGORITHM { get; set; }
        public string sub { get; set; }
        public string KEYFACTORY { get; set; }
        public string JWT_TYPE { get; set; }

    }
}
