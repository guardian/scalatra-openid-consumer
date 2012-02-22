package com.gu.scalatra.openid

import org.openid4java.consumer.ConsumerManager
import org.openid4java.message.{AuthSuccess, ParameterList}
import org.openid4java.message.ax.{FetchResponse, AxMessage, FetchRequest}
import org.scalatra.{CookieSupport, ScalatraKernel}
import com.gu.security.{MacService, KeyService}

trait OpenIdConsumer extends ScalatraKernel with UserAuthorisation with CookieSupport {

  val authenticationReturnUri: String
  val authenticationReturnPath: String
  val protectedPaths: List[String]
  val discoveryEndpoint: String
  val logoutPath: String
  val logoutRedirect: String
  val secretKey: String

  lazy val discovered = "discovered"
  lazy val redirectTo = "redirectTo"
  lazy val email = "email"
  lazy val firstName = "firstname"
  lazy val lastName = "lastname"
  lazy val emailSchema = "http://schema.openid.net/contact/email"
  lazy val firstNameSchema = "http://axschema.org/namePerson/first"
  lazy val lastNameSchema = "http://axschema.org/namePerson/last"

  lazy val manager = new ConsumerManager
  lazy val keyService = new KeyService(secretKey)
  lazy val macService = new MacService(keyService.getSecretKeySpec)
  lazy val cookieRegEx = "^^([\\w\\W]*)>>([\\w\\W]*)$".r
  lazy val hashSeparator = ">>"
  lazy val userCookiePattern = "%s|%s|%s" + hashSeparator

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
      cookies.get(User.key) match {
        case Some(cookie) => {
          cookieRegEx.split(cookie) match {
            case cookieRegEx(userCookie, hash) => {
              if (!(macService.getMacForMessageAsHex(userCookie + hashSeparator) == hash)) {
                clearCookie(User.key)
                redirect(authenticationProviderRedirectEndpoint)
              }
            }
            case _ => // Do nothing
          }

        }
        case _ => redirect(authenticationProviderRedirectEndpoint)
      }
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
        val value = userCookiePattern.format(userEmail, userFirstName, userLastName)
        val valueHash = macService.getMacForMessageAsHex(value)
        cookies.set(User.key, value + valueHash)
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
    cookies.delete(cookieName)
  }
  
  get(logoutPath) {
    session.invalidate()
    getAndClearCookie(User.key)
    redirect(logoutRedirect)
  }

}