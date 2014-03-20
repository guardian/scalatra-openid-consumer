package com.gu.scalatra.openid

import org.openid4java.consumer.ConsumerManager
import org.openid4java.message.{AuthSuccess, ParameterList}
import org.openid4java.message.ax.{FetchResponse, AxMessage, FetchRequest}
import com.gu.scalatra.security.{KeyService, MacService, SecretKey}
import org.scalatra.ScalatraKernel

trait OpenIdConsumer extends ScalatraKernel with UserAuthorisation with StorageStrategy {

  def authenticationReturnUri: String
  def authenticationReturnPath: String
  def protectedPaths: List[String]
  def discoveryEndpoint: String
  def sendAssocHandle: Boolean = true
  def logoutPath: String
  def logoutRedirect: String
  def authErrorRedirect: String

  // By default, redirect to the URL originally hit when the auth journey started
  def redirectToUri: String = {
    val optionalParams = Option(request.getQueryString).map("?" + _) getOrElse ""
    request.getRequestURI + optionalParams
  }

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
    storeRedirectToUri(redirectToUri)
    val authReq = manager.authenticate(manager.associate(discoveries), authenticationReturnUri)
    val fetch = FetchRequest.createFetchRequest()
    fetch.addAttribute(email, emailSchema, true)
    fetch.addAttribute(firstName, firstNameSchema, true)
    fetch.addAttribute(lastName, lastNameSchema, true)
    authReq.addExtension(fetch)
    if (!sendAssocHandle) { authReq.setHandle(" ") }
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
        isUserAuthorised(user) match {
          case Authorised => {
            storeUser(user)
            val redirectUrl = getRedirectToUri
            clearRedirectToUrl()
            redirect(redirectUrl)
          }
          case Refused(error) => {
            clearUser()
            // TODO: cleaner GET param appending
            redirect(authErrorRedirect + s"?email=$userEmail&errorType=authorisation&errorKey=$error")
          }
        }
      }
    } else
      redirect(authErrorRedirect + s"?errorType=authentication&errorKey=provider")
  }

  get(logoutPath) {
    clearUser()
    redirect(logoutRedirect)
  }

}

