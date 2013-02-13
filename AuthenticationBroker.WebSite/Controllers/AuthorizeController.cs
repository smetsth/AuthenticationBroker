using System.Web.Mvc;
using WindowsAzure.Acs.Oauth2;

namespace AuthenticationBroker.WebSite.Controllers
{
    [Authorize]
    public class AuthorizeController
        : AuthorizationServer
    {
    }
}
