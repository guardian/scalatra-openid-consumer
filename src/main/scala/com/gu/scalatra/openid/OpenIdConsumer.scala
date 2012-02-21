package com.gu.scalatra.openid

import org.openid4java.consumer.ConsumerManager
import org.openid4java.discovery.DiscoveryInformation
import org.openid4java.message.{AuthSuccess, ParameterList}
import org.openid4java.message.ax.{FetchResponse, AxMessage, FetchRequest}
import org.scalatra.{CookieSupport, ScalatraKernel, CookieOptions, Cookie}

trait OpenIdConsumer extends ScalatraKernel with UserAuthorisation with CookieSupport {

  val authenticationReturnUri: String
  val authenticationReturnPath: String
  val protectedPaths: List[String]
  val discoveryEndpoint: String
  val logoutPath: String
  val logoutRedirect: String

  lazy val discovered = "discovered"
  lazy val redirectTo = "redirectTo"
  lazy val email = "email"
  lazy val firstName = "firstname"
  lazy val lastName = "lastname"
  lazy val emailSchema = "http://schema.openid.net/contact/email"
  lazy val firstNameSchema = "http://axschema.org/namePerson/first"
  lazy val lastNameSchema = "http://axschema.org/namePerson/last"
  lazy val manager = new ConsumerManager

  def authenticationProviderRedirectEndpoint() = {
    val discoveries = manager.discover(discoveryEndpoint)
    cookies.set(redirectTo, request.getRequestURI)
    val authReq = manager.authenticate(manager.associate(discoveries), authenticationReturnUri)
    val fetch = FetchRequest.createFetchRequest()
    fetch.addAttribute(email, emailSchema, true)
    fetch.addAttribute(firstName, firstNameSchema, true)
    fetch.addAttribute(lastName, lastNameSchema, true)
    authReq.addExtension(fetch)
    authReq.getDestinationUrl(true)
  }

  protectedPaths map { path =>
    before(path) {
      if(cookies.get(User.key) == None)
        redirect(authenticationProviderRedirectEndpoint)
    }
  }

  get(authenticationReturnPath) {
    val openidResp = new ParameterList(request.getParameterMap())
    val discoveries = manager.discover(discoveryEndpoint)
    val verification = manager.verify(authenticationReturnUri, openidResp, manager.associate(discoveries))
    val verified = verification.getVerifiedId()
    if (verified != null) {
      val authSuccess = verification.getAuthResponse().asInstanceOf[AuthSuccess]
      if (authSuccess.hasExtension(AxMessage.OPENID_NS_AX)){
        val fetchResp = authSuccess.getExtension(AxMessage.OPENID_NS_AX).asInstanceOf[FetchResponse]
        val emails = fetchResp.getAttributeValues(email)
        val userEmail = emails.get(0).asInstanceOf[String]
        val userFirstName = fetchResp.getAttributeValue(firstName)
        val userLastName = fetchResp.getAttributeValue(lastName)
        val user = User(userEmail, userFirstName, userLastName)
        if (!isUserAuthorised(user)){
          clearCookie(User.key)
          halt(status = 403, reason = "Sorry, you are not authorised")
        }
        cookies.set(User.key, "%s|%s|%s".format(userEmail, userFirstName, userLastName))
        val redirectToUri = getAndClearCookie(redirectTo)
        redirect(redirectToUri)
      }
    } else
      halt(status = 403, reason = "Could not verify authentication with provider")
  }

  def getAndClearCookie(cookieName: String): String = {
    val cookie = cookies(cookieName)
    clearCookie(cookieName)
    cookie
  }
  
  def clearCookie(cookieName: String) {
    cookies.get(cookieName) foreach { _ => cookies.update(cookieName, null) }
  }
  
  get(logoutPath) {
    session.invalidate()
    getAndClearCookie(User.key)
    redirect(logoutRedirect)
  }

}