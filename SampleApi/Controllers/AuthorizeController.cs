using System.Web.Mvc;
using WindowsAzure.Acs.Oauth2;

namespace SampleApi.Controllers
{
    [Authorize]
    public class AuthorizeController
        : AuthorizationServer
    {
    }
}
