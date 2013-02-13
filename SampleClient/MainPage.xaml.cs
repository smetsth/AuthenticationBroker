using System;
using System.Net.Http;
using System.Net.Http.Headers;
using Windows.Security.Authentication.Web;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Navigation;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=234238

namespace SampleClient
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        private string _token;
        public MainPage()
        {
            this.InitializeComponent();
        }

        /// <summary>
        /// Invoked when this page is about to be displayed in a Frame.
        /// </summary>
        /// <param name="e">Event data that describes how this page was reached.  The Parameter
        /// property is typically used to configure the page.</param>
        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
        }

        private async void GetToken(object sender, RoutedEventArgs e)
        {
            Log("Getting token");

            var response = await WebAuthenticationBroker.AuthenticateAsync(
                    WebAuthenticationOptions.None,
                    new Uri("https://waabs.azurewebsites.net/auth/broker/login"),
                    new Uri("https://waabs.azurewebsites.net/auth/broker/end"));

            if (response.ResponseStatus == WebAuthenticationStatus.Success)
            {
                var queryParamName = "?acsToken=";
                var queryParamNameIndex = response.ResponseData.IndexOf(queryParamName);
                _token = response.ResponseData.Substring(queryParamNameIndex + queryParamName.Length);

                Log(string.Format("Your token = '{0}'", _token));
            }
            else
            {
                Log(string.Format("Response: {0}{1}ResponseData: {1}{2}ErrorDetail: {1}{3}", 
                    response.ResponseStatus, Environment.NewLine, 
                    response.ResponseData, 
                    response.ResponseErrorDetail));
            }
        }

        private async void CallApi(object sender, RoutedEventArgs e)
        {
            var client = new HttpClient { BaseAddress = new Uri("http://localhost:25575/") };

            client.DefaultRequestHeaders.Authorization =
                        new AuthenticationHeaderValue("Bearer", _token);

            var response = await client.GetAsync("api/values");
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            {
                Log(response.Headers.Location + Environment.NewLine + response.ReasonPhrase);
            }
            else
            {
                Log(response.Headers.Location + Environment.NewLine + await response.Content.ReadAsStringAsync());
            }
        }

        private void Log(string text)
        {
            txtLog.Text = text;
        }
    }
}
