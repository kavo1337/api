using Microsoft.EntityFrameworkCore;

namespace API.DataDBContext
{
    public class DataDBContext(DbContextOptions<DataDBContext> opt) : DbContext(opt)
    {

    }
}
