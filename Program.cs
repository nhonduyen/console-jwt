using System;
using System.Threading.Tasks;
using Newtonsoft.Json;
// https://houseofcat.io/tutorials/csharp/identity/createjwt
// check token: https://jwt.io/
// https://www.jerriepelser.com/blog/manually-validating-rs256-jwt-dotnet/
namespace token
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var user = new User { UserId = 1, EmailAddress = "nhonduyen@gmail.com", FullName = "Ted Hammington",
            FirstName = "Ted", LastName = "Hammington" };
            var userData = new UserData { AccountId = 1 };
            var issuer = "127.0.0.1";
            var authority = "127.0.0.1";

            //Issuer & Authority Note: If your app or API is the issuer and authority they will be the exact same field. They but don't have to be, key distinction.

            //256-bit string generated on https://passwordsgenerator.net/

            var privateKey = "eEbzxsc5KfA6N4CgcyyBWSbkv96EN3WYE8j8uH42kQu2rtpqVLatKpxVXt4DENG5zJsaVAgUAkvfZECdLPVquvZAWT3u2eJZbUcWgyQv4fXQkLPQ66WCNSaeUyGJmC6EnjwKbLP7yJatRzwtArJQW7ChpnhLW5rmk8z2md7qLhdwtqFyPPTVjed6B6GmQuEjcU7DsYzyC4MwHyvkFmdsAHaUaN4Dn5tJE5GaXNzDnYssQL9rnSm2JHvE4tHVYkd2";
            var validDays = 7;

            var createJwt = await TokenManager.CreateJWTAsync(user, userData, issuer, authority, privateKey, validDays);
            Console.WriteLine("Token created");
            Console.WriteLine(createJwt);
          
            var validUser = await TokenManager.ValidateToken(createJwt).ConfigureAwait(false);

            Console.WriteLine("Validate token");
            Console.WriteLine(validUser);

            Console.WriteLine($"Valid time:  {validUser.ValidFrom} ~ {validUser.ValidTo}");                   
        }
    }
}
