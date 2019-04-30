using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace token 
{
    public class TokenManager 
    {
        public static Task<ClaimsIdentity> CreateClaimsIdentityAsync (User user, UserData userData) 
        {
            var claimsIdentity = new ClaimsIdentity ();
            claimsIdentity.AddClaim (new Claim (ClaimTypes.Email, user.EmailAddress));
            claimsIdentity.AddClaim (new Claim (ClaimTypes.NameIdentifier, user.UserId.ToString ()));
            claimsIdentity.AddClaim (new Claim (ClaimTypes.Name, user.FullName ?? $"{user.FirstName} {user.LastName}"));

            // This next one is kinda of special. This lets you put non-convential JWT data in here in the format you desire.
            // DO NOT ABUSE IT! If your tokens get too fat you aren't using them as intended (as identity). You
            // will only hurt yourself in the long run.

            claimsIdentity.AddClaim (new Claim (ClaimTypes.UserData, JsonConvert.SerializeObject (userData)));

            // Keep the UserData field small, such as just Ids that can then be used to look up data you need.
            // Instead of getting just a UserId and having to look up their LibraryId, you can  go straight
            // to using a LibraryId stored in the user data to look up books checked out.
            // It accepts any string as value, so it could be json, or csv, or tsv, etc. I chose a Json string for this
            // demo.

            // TODO: Roles. You need to connect to your database here to get the ACTUAL roles that you may
            // already be using. Some common examples are Security.UserRoles or dbo.UserRoles. Wherever your
            // roles are, you need to do that. Your schema is up for you to figure out or even create.
            // ex.) var roles = await _userRepository.GetRolesAsync(userId);
            // Use the Role model as an example of the data you need to acquire.
            // Roles could be Student, Employee, Trainer, Admin, etc.

            var roles = new List<Role> ();
            roles.Add (new Role { RoleId = 1, RoleName = "admin" });
            foreach (var role in roles) 
            {
                claimsIdentity.AddClaim (new Claim (ClaimTypes.Role, role.RoleName));
            }

            return Task.FromResult (claimsIdentity);
        }

        public static async Task<string> CreateJWTAsync (
            User user,
            UserData userData,
            string issuer,
            string authority,
            string symSec,
            int daysValid) 
        {
            var tokenHandler = new JwtSecurityTokenHandler ();
            var claims = await CreateClaimsIdentityAsync (user, userData).ConfigureAwait (false);

            // Create JWT token

            var token = tokenHandler.CreateJwtSecurityToken (
                issuer: issuer,
                audience: authority,
                subject: claims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddDays (daysValid),
                signingCredentials: new SigningCredentials (
                    new SymmetricSecurityKey (
                        Encoding.Default.GetBytes (symSec)),
                    SecurityAlgorithms.HmacSha256Signature)

            );

            return tokenHandler.WriteToken (token);
        }

        public static Task<SecurityToken> ValidateToken (string token) 
        {
            SecurityToken validatedToken;
            var validateParameter = new TokenValidationParameters 
            {
                ValidIssuer = "127.0.0.1",
                ValidAudience = "127.0.0.1",
                IssuerSigningKey =
                new SymmetricSecurityKey (
                Encoding.Default.GetBytes ("eEbzxsc5KfA6N4CgcyyBWSbkv96EN3WYE8j8uH42kQu2rtpqVLatKpxVXt4DENG5zJsaVAgUAkvfZECdLPVquvZAWT3u2eJZbUcWgyQv4fXQkLPQ66WCNSaeUyGJmC6EnjwKbLP7yJatRzwtArJQW7ChpnhLW5rmk8z2md7qLhdwtqFyPPTVjed6B6GmQuEjcU7DsYzyC4MwHyvkFmdsAHaUaN4Dn5tJE5GaXNzDnYssQL9rnSm2JHvE4tHVYkd2")),
            };
            var handler = new JwtSecurityTokenHandler ();

            var user = handler.ValidateToken(token, validateParameter, out validatedToken);

            return Task.FromResult(validatedToken);
        }
    }
}