using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Nancy.Security;

namespace Nancy.Authentication.FacebookSdk
{
    public class NancyFacebookIdentity : IUserIdentity
    {
        public string AccessToken { get; set; }
        public IEnumerable<string> Claims { get; set; }
        public string UserName { get; set; }
    }
}
