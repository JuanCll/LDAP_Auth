using AuthMS;
using AuthMS.Models;
using AuthMS.DataBase;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Configuration;
using System.Data.Entity;
using System.IdentityModel.Tokens.Jwt;
using System.Numerics;
using System.Security.Claims;
using System.Security.Cryptography;
using Azure.Core;
using System.Data.SqlClient;
using System.Text;
using Microsoft.AspNetCore.Identity;
using System.Drawing;
using System.Text.Json.Serialization;
using System.Text.Json;
using System.DirectoryServices.Protocols;
using LDAPc.Models;
using System.Net;
using System;
using System.Diagnostics;

namespace AuthMs.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static Credential credential = new Credential();

        private readonly IConfiguration _configuration;

        private readonly DataBaseContext _dataBaseContext;

        private readonly UserManager<IdentityUser> _userManager;

        //String ConnectionString = "Server=authmsdbc;Database=credentialdb;User ID=SA;Password=Password1!;MultipleActiveResultSets=true;Trusted_Connection=False;TrustServerCertificate=true";
        //35.198.44.17        SA
        public AuthController(IConfiguration configuration, DataBaseContext dataBaseContext)
        {
            _configuration = configuration;
            _dataBaseContext = dataBaseContext;
            //_userManager = userManager;

        }
        /*
        [HttpPost("register")]
        public async Task<ActionResult<Credential>> Register(CredentialDto request)
        {
            string inputUserId = request.UserId.ToString();
            string inputPassword = request.Password.ToString();        

            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            
            credential.UserId = request.UserId;
            credential.PasswordHash = passwordHash;
            credential.PasswordSalt = passwordSalt;

            _dataBaseContext.Database.OpenConnection();
            _dataBaseContext.Database.ExecuteSqlRaw("SET IDENTITY_INSERT dbo.Credentials ON");
            _dataBaseContext.Credentials.Add(credential);
            _dataBaseContext.SaveChanges();
            _dataBaseContext.Database.ExecuteSqlRaw("SET IDENTITY_INSERT dbo.Credentials OFF");
            _dataBaseContext.Database.CloseConnection();

            //_dataBaseContext.Credentials.Add(credential);
            //_dataBaseContext.SaveChanges();
            
            //return BadRequest("Error al registrar");
            return Ok(credential);

        }
        
        */
        string Token_bu { get; set; }

        /*
        //Login .NET
        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(CredentialDto request)
        {
            string inputUserId= request.UserId.ToString();
            string inputPassword= request.Password.ToString();
            if  (!VerifyUserID(inputUserId))
            {
                return BadRequest("Usuario no encontrado");
            }

            if (!VerifyPassword(inputUserId, inputPassword))
            {
                return BadRequest("Contraseña incorrecta");
            }

            //byte[] passwordGuardada = VerPassword(inputUserId);
            
            string token = CreateToken(credential);

            var userIDclaim = inputUserId;


            var token_id = Tuple.Create(token, userIDclaim);
            var token_idJson= JsonSerializer.Serialize(token_id);

            return Ok(token_idJson);
            
        }
        */

        //Login LDAP 

        [HttpPost("login")]
        public async Task<IActionResult> Login(CredentialLDAP credentials)
        {

            string ldapServer = "wings-ldap"; //localhost o wings-ldap depende 
            int ldapPort = 389;
            string ldapUserId = "cn=admin";
            string ldapPassword = "admin";
            string ldapBaseDn = "dc=wings,dc=co";


            try
            {
                using (LdapConnection connection =
                    new LdapConnection(new LdapDirectoryIdentifier(ldapServer, ldapPort)))
                {
                    connection.SessionOptions.ProtocolVersion = 3;
                    connection.SessionOptions.SecureSocketLayer = false;
                    connection.AuthType = AuthType.Basic;
                    //connection.Credential = new NetworkCredential(ldapUserId, ldapPassword);
                    NetworkCredential nc = new NetworkCredential("cn=admin,dc=wings,dc=co", "admin");

                    connection.Bind(nc);

                    string userDn = $"cn={credentials.UserId}," + "ou=sa," + ldapBaseDn;

                    string userPassword = credentials.Password;

                    try
                    {
                        connection.Bind(new NetworkCredential(userDn, userPassword));
                        string token = CreateToken(credential, credentials.UserId);

                        var userIDclaim = credentials.UserId;


                        var token_id = Tuple.Create(token, userIDclaim);
                        var token_idJson = JsonSerializer.Serialize(token_id);

                        return Ok(token_idJson);
                        
                    }
                    catch (LdapException e)
                    {
                        return BadRequest("LDAP error: Credenciales incorrectas");
                    }

                }
            }
            catch (Exception e)
            {
                string Message = e.Message;
                string StackTrace = e.StackTrace;
                var err = Tuple.Create(Message, StackTrace);
                var err_tuple = JsonSerializer.Serialize(err);

                return BadRequest(err_tuple);
            }
        }

        /*
        private bool VerifyUserID(string userid) {
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                string selectQuery = "SELECT UserID FROM Credentials WHERE UserID = @UserID";
                SqlCommand command = new SqlCommand(selectQuery, connection);
                command.Parameters.AddWithValue("@UserID", userid);
     
                using (SqlDataReader reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        string storedUserID = reader["UserID"].ToString();
                        
                        connection.Close();
                        return userid == storedUserID;
                        
                    }
                    connection.Close();
                    return false;                   
                }              
            }
        }
        */

        /*private byte[] VerPassword(string userid)
        {
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                string selectQuery = "SELECT * FROM Credentials WHERE UserID = @UserID";
                SqlCommand commandP = new SqlCommand(selectQuery, connection);
                commandP.Parameters.AddWithValue("@UserID", userid);

                using (SqlDataReader reader = commandP.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        string storedUserID = reader["UserID"].ToString();

                        byte[] storedPasswordHash = (byte[])reader["PasswordHash"];
                        byte[] storedPasswordSalt = (byte[])reader["PasswordSalt"];

                        connection.Close();
                        
                        return storedPasswordHash;
                    }
                    connection.Close();
                    byte[] valor = { 64, 45 };
                    return valor;
                }
            }
        }*/

        /*
        private bool VerifyPassword(string userid,string password)
        {
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                string selectQuery = "SELECT * FROM Credentials WHERE UserID = @UserID";
                SqlCommand command = new SqlCommand(selectQuery, connection);
                command.Parameters.AddWithValue("@UserID", userid);

                using (SqlDataReader reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        byte[] storedPasswordHash = (byte[])reader["PasswordHash"];
                        byte[] storedPasswordSalt = (byte[])reader["PasswordSalt"];

                        bool verifiedpassword = VerificarPasswordHash(password, storedPasswordHash,storedPasswordSalt);

                        return verifiedpassword;
                    }                   
                    return false;
                }
            }
        }
        */

        [HttpPost("validate")]
        public ActionResult<bool> Validate(string tokenApi)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var token = tokenHandler.ReadJwtToken(tokenApi);
                var roleClaim = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role);
                var roleTK = roleClaim.Value;

                if (roleTK == "Pilot")
                {
                    Console.WriteLine("{0}", Token_bu);
                    //Console.WriteLine("{0}", tokenApi);
                    return true;
                }
                Console.WriteLine("{0}", Token_bu);
                //Console.WriteLine("{0}", tokenApi);
                return false;
            } catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
            
            
        }


        private string CreateToken(Credential credential,string userName)
        {
            var StringUserId = credential.UserId.ToString();

            List<Claim> claims = new()
            {
                new Claim(ClaimTypes.Name, userName),
                new Claim(ClaimTypes.Role, "Pilot")
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                                        _configuration.GetSection("AppSettings:Token").Value));

            var creden = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creden
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using var hmac = new HMACSHA512();
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));

        }

        private bool VerificarPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using var hmac = new HMACSHA512(passwordSalt);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            return computedHash.SequenceEqual(passwordHash);

        }
    }
}
