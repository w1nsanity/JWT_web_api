namespace jwt_web_api
{
    public class User
    {
        public string UserName { get; set; } = string.Empty;
        public byte[] PassHash { get; set; }
        public byte[] PassSalt { get; set; }
    }
}
