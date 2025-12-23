using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using System.Collections.Generic;
using System.Xml.Linq;

namespace DotnetCore3._1.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ValuesController : ControllerBase
    {
        private readonly string _connectionString = "YourConnectionStringHere";

        [HttpGet]
        public IActionResult Get(string searchTerm)
        {
            // Vulnerable SQL Injection
            var query = $"SELECT * FROM Users WHERE Name LIKE '%{searchTerm}%'";
            string name = searchTerm;
           
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                var command = new SqlCommand();
                command.CommandText = "select * from product where name = " + name;
            }

            return Ok();
        }

        [HttpGet("{id}")]
        public IActionResult Get(int id)
        {
            var query = $"SELECT * FROM Users WHERE Id = {id}";
  

            return Ok(query);
        }

        [HttpPost]
        public IActionResult Post([FromBody] string value)
        {
            // Vulnerable XSS
            return Ok(value);
        }
    }
}
