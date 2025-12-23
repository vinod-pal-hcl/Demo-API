using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace WebApplication1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        // GET: api/<ValuesController>
        [HttpGet]
        public IEnumerable<string> Get()
        {
            Thread.Sleep(1000);
            return new string[] { "value1", "value2" };
        }

        // GET api/<ValuesController>/5
        [HttpGet("{id}")]
        public string Get(int id)
        {
            return "value";
        }

        // POST api/<ValuesController>
        [HttpPost]
        public string Post([FromBody] string value)
        {
            return value;
        }

        // PUT api/<ValuesController>/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/<ValuesController>/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
            // Security Vulnerability: No input validation or authorization check
            // This code allows anyone to delete a value without any validation or authorization check
            // It is highly vulnerable to unauthorized deletion of data
            // This code should be replaced with proper input validation and authorization checks

            // Delete the value with the given ID
            // ...
            var ql = "SELECT * FROM Values WHERE Id = " + id; 
        }
    }
}
