using System;
using System.Collections.Specialized;
using System.Configuration;
using System.IO;
using System.IdentityModel.Protocols.WSTrust;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using System.Xml;
using WindowsAzure.Acs.Oauth2;
using WindowsAzure.Acs.Oauth2.Protocol.Swt;

namespace AuthenticationBroker.WebSite.Areas.Auth.Controllers
{
    /// <summary>
    ///     Notes on the WebAuthenticationBroker
    ///     1) Publicly accessible URI
    ///     2) Return URL cannot be too long. Don't know the exact limit.
    ///     3) The end method must return OK and an empty body. So only data in the URL
    /// </summary>
    public class BrokerController : Controller
    {
        private readonly string _acsRealm;
        private readonly string _clientId;
        private readonly string _clientName;
        private readonly string _clientRedirectUri;
        private readonly string _clientSecret;
        private readonly ApplicationRegistrationService _registrationService;
        private readonly string _swtSigningKey;

        public BrokerController()
        {
            _clientId = ConfigurationManager.AppSettings["OAuthClient.Id"];
            _clientSecret = ConfigurationManager.AppSettings["OAuthClient.Secret"];
            _clientRedirectUri = ConfigurationManager.AppSettings["OAuthClient.RedirectUri"];
            _clientName = ConfigurationManager.AppSettings["OAuthClient.Name"];

            _swtSigningKey = ConfigurationManager.AppSettings["WindowsAzure.OAuth.SwtSigningKey"];
            _acsRealm = ConfigurationManager.AppSettings["WindowsAzure.OAuth.RelyingPartyRealm"];
            _registrationService = new ApplicationRegistrationService();
        }

        public ActionResult Login()
        {
            ApplicationRegistration app = _registrationService.GetApplication(_clientId);

            if (app == null)
            {
                _registrationService.RegisterApplication(_clientId, _clientSecret, _clientRedirectUri, _clientName);
            }

            string location =
                string.Format("https://{0}.accesscontrol.windows.net:443/v2/wsfederation?wa=wsignin1.0&wtrealm={1}",
                              _registrationService.ServiceNamespace,
                              HttpUtility.UrlEncode(_acsRealm));

            Response.StatusCode = (int)HttpStatusCode.Redirect;
            Response.Headers.Add("Location", location);
            Response.End();

            return null;
        }


        public ActionResult Callback()
        {
            string input;
            using (var reader = new StreamReader(Request.InputStream))
            {
                input = reader.ReadToEnd();
            }

            string locationBase = string.Format("{0}/auth/broker/end",
                                                Request.Url.GetComponents(UriComponents.SchemeAndServer,
                                                                          UriFormat.Unescaped));
            var inputInQueryStringUri = new Uri(locationBase + "?" + input);
            NameValueCollection tokenValues = inputInQueryStringUri.ParseQueryString();
            string tokenData = tokenValues["wresult"];

            //Validate SWT token
            var tokenSerializer = new WSTrustFeb2005ResponseSerializer();
            RequestSecurityTokenResponse requestSecrityTokenResponse =
                tokenSerializer.ReadXml(new XmlTextReader(new StringReader(tokenData)),
                                        new WSTrustSerializationContext());


            var simpleWebTokenHandler = new SimpleWebTokenHandler("https://" + _registrationService.ServiceNamespace + ".accesscontrol.windows.net/", _swtSigningKey);
            var securityToken = simpleWebTokenHandler.ReadToken(requestSecrityTokenResponse.RequestedSecurityToken.SecurityTokenXml.InnerText) as SimpleWebToken;
            simpleWebTokenHandler.ValidateToken(securityToken, _acsRealm);

            //Create delegation in ACS
            var authServerIdentifier = securityToken.Claims.FirstOrDefault(c => c.ClaimType == ClaimTypes.NameIdentifier);
            var authServerIdentity = new AuthorizationServerIdentity
                                         {
                                             NameIdentifier = authServerIdentifier.Value,
                                             IdentityProvider = authServerIdentifier.Issuer
                                         };

            //todo: Check if we can add some claims (role claims) to the scope
            string code = _registrationService.GetAuthorizationCode(_clientId, authServerIdentity, "scope");


            //todo: use OAuth parameter names in the return URL
            //return the token
            string location = string.Format("{0}?acsToken={1}", locationBase, code);

            Response.StatusCode = (int)HttpStatusCode.Redirect;
            Response.Headers.Add("Location", location);
            Response.End();


            return null;
        }


        public ActionResult End()
        {
            this.
            Response.StatusCode = (int)HttpStatusCode.OK;
            this.Response.End();

            return null;
        }

    }
}