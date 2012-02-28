package com.gu.scalatra.openid

trait GoogleOpenIdConsumer extends OpenIdConsumer {

  lazy val discoveryEndpoint = "https://www.google.com/accounts/o8/id"

}