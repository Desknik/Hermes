namespace SimpleNewsSystem.Models;

public class User
{
    public int id { get; set; }
    public required string email { get; set; }
    public required string password { get; set; }
    public bool is_admin { get; set; }
}