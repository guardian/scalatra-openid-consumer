# Scalatra OpenID Consumer

This project aims to make it easy to include OpenID as an authentication mechanism into your Scalatra based project.

## Implementations

Currently the only consumer implementation is for Google. This is all Google accounts and is not restricted to a given Google Apps domain.

In order to create more implementations, only the 'discovery' endpoint should be required for each additional provider.

## Usage

Add the following resolver in sbt:

    "Guardian GitHub Release" at "http://guardian.github.com/maven/repo-releases"
    
And include the project:    
    
    "com.gu" %% "scalatra-openid-consumer" % "0.1.6"

The current version is 0.1.6 and is available for Scala 2.8.1, 2.9.0_1 and 2.9.1 and is dependent on Scalatra 2.0.2

In your filter class mixin the *OpenIdConsumer* trait along with the *UserAuthorisation* trait.  This project provides a default in-memory implementation for user authorisation, and includes one OpenId provider (Google) and the storage strategy (Cookie or Session).  It should be possible to extend *OpenIdConsumer* to support other providers.  For example:

    class Dispatcher extends ScalatraFilter with GoogleOpenIdConsumer with CookieStorageStrategy with AlwaysAllowUserAuthorisation

Within this class, you will need to set a series of values for the trait.
   
    val authenticationReturnUri: String             // the full request URI: domain, port, context and path; where clients are returned too after being sent to the provider
    val authenticationReturnPath: String            // the endpoint that the provider will send the client back to, i.e. /auth/verify
    val protectedPaths: List[String]                // a list of paths to protect using the OpenId trait, i.e. List("/protect*", "/private*")
    val discoveryEndpoint: String                   // set within the GoogleOpenIdConsumer, but can be replaced for other providers
    val logoutPath: String                          // the endpoint where the the client can log out from
    val logoutRedirect: String                      // the endpoint where the trait will send the client to after the client has been logged out
    val secretKey: String                           // your apps secret key used for signing cookies - only required by the CookieStorageStrategy

## Contributing

If you wish to contribute, please fork the project. Then create a new remote branch with your changes and send a pull request and we will try and add your changes in.

## Code overview

### User authorisation

This trait is for informing the application that an authentication has been successful and gives the application a chance to reject that user based on some criteria which this extension would not know about, a banned user for example.

Again, there is a default implementation which allows all users in.

### User

This case class contains the email, first name and last name of the authenticated user. You can retrieve the user in your code by calling the getUser method provided by the StorageStrategy you have mixed in

### OpenIdConsumer

This trait is where all the hard work is, and contains Scalatra filter endpoints for accepting an authorisation request from the provider as well as setting up what routes to protect.

The only implementation for this so far is the GoogleOpenIdConsumer.

## Publishing

Publishing is currently controlled through the Guardian Github repository of which you will need to be a member of.  If you are, follow these instructions:

    cd ~
    git clone git@github.com:guardian/guardian.github.com.git
    (in sbt): +publish
    cd ~/guardian.github.com
    git add <add new files>
    git commit -m "<commit message>"
    git push

When Github Pages publishes the changes, they will be available in the Maven repository.