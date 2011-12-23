package com.gu.scalatra.openid

import org.openid4java.consumer.ConsumerManager
import org.openid4java.discovery.DiscoveryInformation
import org.openid4java.message.{AuthSuccess, ParameterList}
import org.openid4java.message.ax.{FetchResponse, AxMessage, FetchRequest}
import org.scalatra.ScalatraKernel

trait OpenIdConsumer extends ScalatraKernel with UserAuthorisation {

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
    val discoveryInformation = manager.associate(discoveries)
    session.setAttribute(discovered, discoveryInformation)
    session.setAttribute(redirectTo, request.getRequestURI)
    val authReq = manager.authenticate(discoveryInformation, authenticationReturnUri)
    val fetch = FetchRequest.createFetchRequest()
    fetch.addAttribute(email, emailSchema, true)
    fetch.addAttribute(firstName, firstNameSchema, true)
    fetch.addAttribute(lastName, lastNameSchema, true)
    authReq.addExtension(fetch)
    authReq.getDestinationUrl(true)
  }

  protectedPaths map { path =>
    before(path) {
      if(!session.contains(User.key))
        redirect(authenticationProviderRedirectEndpoint)
    }
  }

  get(authenticationReturnPath) {
    val openidResp = new ParameterList(request.getParameterMap())
    val discoveryInformation = session.getAttribute(discovered).asInstanceOf[DiscoveryInformation]
    val verification = manager.verify(authenticationReturnUri, openidResp, discoveryInformation)
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
          session.invalidate()
          halt(status = 403, reason = "Sorry, you are not authorised")
        }
        session(User.key) = user
        val redirectToUri = session.getAttribute(redirectTo).asInstanceOf[String]
        redirect(redirectToUri)
      }
    } else
      halt(status = 403, reason = "Could not verify authentication with provider")
  }

  get(logoutPath) {
    session.invalidate()
    redirect(logoutRedirect)
  }

}