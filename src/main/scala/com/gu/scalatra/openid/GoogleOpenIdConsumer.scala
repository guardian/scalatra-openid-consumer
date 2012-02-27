package com.gu.scalatra.openid

trait GoogleOpenIdConsumer extends OpenIdConsumer with OpenIdConsumerCookieSupport {

  lazy val discoveryEndpoint = "https://www.google.com/accounts/o8/id"

}