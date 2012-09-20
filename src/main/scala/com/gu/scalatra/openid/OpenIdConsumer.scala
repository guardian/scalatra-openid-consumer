package com.gu.scalatra.openid

import org.openid4java.consumer.ConsumerManager
import org.openid4java.message.{AuthSuccess, ParameterList}
import org.openid4java.message.ax.{FetchResponse, AxMessage, FetchRequest}
import com.gu.scalatra.security.{KeyService, MacService, SecretKey}
import org.scalatra.ScalatraKernel

trait OpenIdConsumer extends ScalatraKernel with UserAuthorisation with StorageStrategy {

  val authenticationReturnUri: String
  val authenticationReturnPath: String
  val protectedPaths: List[String]
  val discoveryEndpoint: String
  val logoutPath: String
  val logoutRedirect: String

  lazy val discovered = "discovered"
  lazy val email = "email"
  lazy val firstName = "firstname"
  lazy val lastName = "lastname"
  lazy val emailSchema = "http://schema.openid.net/contact/email"
  lazy val firstNameSchema = "http://axschema.org/namePerson/first"
  lazy val lastNameSchema = "http://axschema.org/namePerson/last"

  lazy val manager = new ConsumerManager

  def authenticationProviderRedirectEndpoint() = {
    val discoveries = manager.discover(discoveryEndpoint)
    val optionalParams = Option(request.getQueryString).map("?" + _) getOrElse ""
    val fullUri = request.getRequestURI + optionalParams
    storeRedirectToUri(fullUri)
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
      if (getUser isEmpty) redirect(authenticationProviderRedirectEndpoint)
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
        if (isUserAuthorised(user)) {
          storeUser(user)
          val redirectUrl = getRedirectToUri
          clearRedirectToUrl()
          redirect(redirectUrl)
        } else {
          clearUser()
          halt(status = 403, reason = "Sorry, you are not authorised")
        }
      }
    } else
      halt(status = 403, reason = "Could not verify authentication with provider")
  }

  get(logoutPath) {
    clearUser()
    redirect(logoutRedirect)
  }

}

