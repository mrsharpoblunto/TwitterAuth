TwitterAuth
===========

A simple C# library for creating signed requests to the Twitter 1.1 API. 

Example usage
-------------

```C#
    //use your real Twitter API tokens here
    string consumerKey = "XXX";
    string consumerSecret = "XXX";
    string accessToken = "XXX";
    string accessTokenSecret = "XXX";

    TwitterAPI api = new TwitterAPI(
                          consumerKey,
                          consumerSecret,
                          accessToken,
                          accessTokenSecret);

    //generate a signed http get request for the specified twitter API URL
    HttpWebRequest signedRequest = api.GenerateSignedGetRequest(
      "https://api.twitter.com/1.1/statuses/user_timeline.json?screen_name=mr_sharpoblunto");

    //you can now use the signedRequest object to query the twitter API
    HttpResponse = (HttpWebResponse)request.GetResponse();
```