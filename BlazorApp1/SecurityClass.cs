namespace BlazorApp1
{
    public class SecurityClass
    {
        public void ExecuteQuery(string query)
        {
            string connectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;";
            using (Microsoft.Data.SqlClient.SqlConnection connection = new Microsoft.Data.SqlClient.SqlConnection(connectionString))
            {
                connection.Open();
                Microsoft.Data.SqlClient.SqlCommand command = new Microsoft.Data.SqlClient.SqlCommand(query, connection);
                command.ExecuteNonQuery();
            }
        }

        // Method with Cross-Site Scripting (XSS) vulnerability
        public string GetHtmlContent(string input)
        {
            return "<div>" + input + "</div>";
        }

        // Method with Insecure Direct Object References (IDOR) vulnerability
        public void DeleteUser(int userId)
        {
            // Delete user with the given ID from the database
            string connectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;";
            using (Microsoft.Data.SqlClient.SqlConnection connection = new Microsoft.Data.SqlClient.SqlConnection(connectionString))
            {
                connection.Open();
                string query = "DELETE FROM Users WHERE UserId = " + userId;
                Microsoft.Data.SqlClient.SqlCommand command = new Microsoft.Data.SqlClient.SqlCommand(query, connection);
                command.ExecuteNonQuery();
            }
        }

        // Method with Unvalidated Redirects and Forwards vulnerability
        public void Redirect(string url)
        {
            // Critical security vulnerability code
            System.Diagnostics.Process.Start(url);
        }
    }
}
