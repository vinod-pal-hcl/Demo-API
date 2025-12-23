using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace DotnetCore3._1
{
    [ApiController]
    [Route("[controller]")]
    public class VulnerableController : ControllerBase
    {
        private readonly string _connectionString = "YourConnectionStringHere";

        [HttpGet]
        public IActionResult Get(string searchTerm)
        {
            // Vulnerable SQL Injection
            var query = $"SELECT * FROM Users WHERE Name LIKE '%{searchTerm}%'";
            return Ok();
        }

        [HttpGet("{id}")]
        public IActionResult Get(int id)
        {
            // Vulnerable Insecure Direct Object Reference
            var query = $"SELECT * FROM Users WHERE Id = {id}";
            // ... (insecure direct object reference code as before)
            return Ok();
        }

        [HttpPost]
        public IActionResult Post([FromBody] string value)
        {
            // Vulnerable XSS
            return Ok(value);
        }

        [HttpPost]
        public IActionResult TransferFunds(int amount, int recipientId)
        {
            // Vulnerable CSRF
            // ... (CSRF code as before)
            return Ok();
        }



        [HttpPost]
        public IActionResult ExecuteCommand(string command)
        {
            // Vulnerable RCE
            var process = Process.Start(new ProcessStartInfo("cmd.exe", "/c " + command));
            // ... (RCE code as before)
            return Ok();
        }
    }
}
