namespace jwt_web_api
{
    public class User
    {
        public string UserName { get; set; } = string.Empty;
        public byte[] PassHash { get; set; }
        public byte[] PassSalt { get; set; }
        public string RefreshToken { get; set; } = string.Empty;
        public DateTime TokenCreated { get; set; }
        public DateTime TokenExpires { get; set; }
    }
}
