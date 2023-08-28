using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthLawan.Models.DTOs
{
    public class RevokeTokenRequest
    {
        public string? RefreshToken { get; set; }
    }
}