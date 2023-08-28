
namespace AuthLawan.Config
{
    public class JwtConfig
    {
        public required string Secret { get; set; }
        public required string ValidAudience { get; set; }
        public required string ValidIssuer { get; set; }

        public TimeSpan ExpiryTimeFrame { get; set; }
    }
}