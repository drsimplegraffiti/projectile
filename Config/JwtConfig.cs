using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthLawan.Config
{
    public class JwtConfig
    {
        public required string Secret { get; set; }
        public required string ValidAudience { get; set; }
        public required string ValidIssuer { get; set; }
    }
}