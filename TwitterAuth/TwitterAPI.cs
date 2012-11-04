using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Security.Cryptography;

namespace TwitterAuth
{
    public class TwitterAPI
    {
        private string ConsumerKey;
        private string AccessToken;
        private string ConsumerSecret;
        private string AccessTokenSecret;

        public TwitterAPI(
            string consumerKey,
            string consumerSecret,
            string accessToken,
            string accessTokenSecret)
        {
            ConsumerKey = consumerKey;
            ConsumerSecret = consumerSecret;
            AccessToken = accessToken;
            AccessTokenSecret = accessTokenSecret;
        }

        /**
         * Creates an httpwebrequest object for a GET request that includes the 
         * required twitter 1.1 API Authorization header
         */
        public HttpWebRequest GenerateSignedGetRequest(
            string fullUrl)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(fullUrl);
            request.Method = "GET";
            request.Headers.Add("Authorization", GenerateGetRequestAuthorizationHeader(fullUrl));
            return request;
        }

        /**
         * Creates an httpwebrequest object for a POST request that includes the 
         * required twitter 1.1 API Authorization header
         */
        public HttpWebRequest GenerateSignedPostRequest(
            string fullUrl,
            string postData)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(fullUrl);
            request.Method = "POST";
            request.Headers.Add("Authorization", GeneratePostRequestAuthorizationHeader(fullUrl, postData));
            return request;
        }

        /**
         * Returns a Twitter 1.1 API authorization header as a string
         */
        public string GenerateGetRequestAuthorizationHeader(
            string fullUrl)
        {
            return GenerateSignedRequest("GET", fullUrl, string.Empty);
        }

        /**
         * Returns a Twitter 1.1 API authorization header as a string
         */
        public string GeneratePostRequestAuthorizationHeader(
            string fullUrl,
            string postData)
        {
            return GenerateSignedRequest("POST", fullUrl, postData);
        }

        private string GenerateSignedRequest(
            string httpMethod,
            string fullUrl,
            string postData)
        {
            Uri parsedUrl = new Uri(fullUrl);
            string baseUrl = parsedUrl.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.Unescaped);

            var authParams = new Dictionary<string, string>();

            //parse out the request parameters
            if (parsedUrl.Query.Length > 0)
            {
                string[] queryParams = parsedUrl.Query.Substring(1).Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var param in queryParams)
                {
                    string[] keyValue = param.Split(new[] { '=' });
                    authParams[Uri.UnescapeDataString(keyValue[0])] = Uri.UnescapeDataString(keyValue[1]);
                }
            }

            //parse out the post parameters
            if (postData.Length > 0)
            {
                string[] postParams = postData.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var param in postParams)
                {
                    string[] keyValue = param.Split(new[] { '=' });
                    authParams[Uri.UnescapeDataString(keyValue[0])] = Uri.UnescapeDataString(keyValue[1]);
                }
            }

            //add in all the oauth parameters
            authParams["oauth_consumer_key"] = ConsumerKey;
            //The nonce is a base64 encoded GUID
            authParams["oauth_nonce"] = Convert.ToBase64String(Guid.NewGuid().ToByteArray()).TrimEnd(new[] { '=' });
            authParams["oauth_signature_method"] = "HMAC-SHA1";

            var timestamp = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            authParams["oauth_timestamp"] = Convert.ToInt64(timestamp.TotalSeconds).ToString();
            authParams["oauth_token"] = AccessToken;
            authParams["oauth_version"] = "1.0";

            //create the signature using all the provided request parameters
            string oauth_signature = CreateSignature(authParams, httpMethod, baseUrl);

            //output the full oauth signature into a format suitable for inclusion on an http
            //authorization header
            StringBuilder headerString = new StringBuilder();
            headerString.Append("OAuth ");
            headerString.Append("oauth_consumer_key=\"");
            headerString.Append(Uri.EscapeDataString(authParams["oauth_consumer_key"]));
            headerString.Append("\", ");
            headerString.Append("oauth_nonce=\"");
            headerString.Append(Uri.EscapeDataString(authParams["oauth_nonce"]));
            headerString.Append("\", ");
            headerString.Append("oauth_signature=\"");
            headerString.Append(Uri.EscapeDataString(oauth_signature));
            headerString.Append("\", ");
            headerString.Append("oauth_signature_method=\"");
            headerString.Append(Uri.EscapeDataString(authParams["oauth_signature_method"]));
            headerString.Append("\", ");
            headerString.Append("oauth_timestamp=\"");
            headerString.Append(Uri.EscapeDataString(authParams["oauth_timestamp"]));
            headerString.Append("\", ");
            headerString.Append("oauth_token=\"");
            headerString.Append(Uri.EscapeDataString(authParams["oauth_token"]));
            headerString.Append("\", ");
            headerString.Append("oauth_version=\"");
            headerString.Append(Uri.EscapeDataString(authParams["oauth_version"]));
            headerString.Append("\"");

            return headerString.ToString();
        }

        private string CreateSignature(
                    Dictionary<string, string> authParams,
                    string httpMethod,
                    string baseUrl)
        {
            var sortedEncodedParams = new List<KeyValuePair<string, string>>();

            //percent encode keys and values
            foreach (var param in authParams)
            {
                sortedEncodedParams.Add(
                    new KeyValuePair<string, string>(
                        Uri.EscapeDataString(param.Key),
                        Uri.EscapeDataString(param.Value)
                ));
            }

            //sort them lexicographically
            sortedEncodedParams.Sort((a, b) =>
            {
                return a.Key.CompareTo(b.Key);
            });

            //dump them into a string
            StringBuilder paramString = new StringBuilder();
            for (int i = 0; i < sortedEncodedParams.Count; ++i)
            {
                paramString.Append(sortedEncodedParams[i].Key);
                paramString.Append('=');
                paramString.Append(sortedEncodedParams[i].Value);
                if (i < sortedEncodedParams.Count - 1) paramString.Append('&');
            }

            //create signature base string
            StringBuilder signatureBaseString = new StringBuilder();
            signatureBaseString.Append(httpMethod.ToUpperInvariant());
            signatureBaseString.Append('&');
            signatureBaseString.Append(Uri.EscapeDataString(baseUrl));
            signatureBaseString.Append('&');
            signatureBaseString.Append(Uri.EscapeDataString(paramString.ToString()));

            //create signing key
            string signingKey =
                Uri.EscapeDataString(ConsumerSecret) +
                "&" +
                Uri.EscapeDataString(AccessTokenSecret);

            //hash the baseString with the signing key
            using (var hash = new HMACSHA1(new ASCIIEncoding().GetBytes(signingKey)))
            {
                string signatureString = Convert.ToBase64String(
                    hash.ComputeHash(
                    new ASCIIEncoding().GetBytes(signatureBaseString.ToString())));
                return signatureString;
            }
        }
    }
}
