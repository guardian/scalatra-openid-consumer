package com.gu.scalatra.openid

import org.openid4java.consumer.ConsumerManager
import org.openid4java.message.{AuthSuccess, ParameterList}
import org.openid4java.message.ax.{FetchResponse, AxMessage, FetchRequest}
import org.scalatra.{CookieSupport, ScalatraKernel}
import com.gu.scalatra.security.{KeyService, MacService, SecretKey}
import org.scalatra.CookieSupport._
import org.scalatra.ScalatraKernel._

trait OpenIdConsumer extends ScalatraKernel with UserAuthorisation with OpenIdConsumerSupport {

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
  lazy val macService = new MacService with SecretKey {def secretKeySpec = keyService.getSecretKeySpec}
  lazy val userRegEx = "^^([\\w\\W]*)>>([\\w\\W]*)$".r
  lazy val hashSeparator = ">>"
  lazy val userKeyPattern = "%s|%s|%s" + hashSeparator

  def authenticationProviderRedirectEndpoint() = {
    val discoveries = manager.discover(discoveryEndpoint)
    redirectTo(request.getRequestURI)
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
      getUser match {
        case Some(userKeyHash) => {
          userRegEx.split(userKeyHash) match {
            case userRegEx(userValue, hash) => {
              if (!macService.verifyMessageAgainstMac(userValue + hashSeparator, hash)) {
                clearUser()
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
          clearUser()
          halt(status = 403, reason = "Sorry, you are not authorised")
        }
        val value = userKeyPattern.format(userEmail, userFirstName, userLastName)
        macService.getMacForMessageAsHex(value) foreach { hash =>
          storeUser(value + hash)
          redirect(getRedirectTo)
        }
      }
    } else
      halt(status = 403, reason = "Could not verify authentication with provider")
  }

  get(logoutPath) {
    session.invalidate()
    clearUser()
    redirect(logoutRedirect)
  }

}

trait OpenIdConsumerSupport {
  def redirectTo(url: String)

  def getRedirectTo: String

  def getUser: Option[String]

  def clearUser()

  def storeUser(keyHash: String)

  def getAndClearCookie(cookieName: String): String

  def clearCookie(cookieName: String)
}

trait OpenIdConsumerCookieSupport extends ScalatraKernel with CookieSupport {
  lazy val redirectToKey = "redirectTo"

  def redirectTo(url: String) {
    cookies.set(redirectToKey, request.getRequestURI)
  }

  def getRedirectTo: String = {
    getAndClearCookie(redirectToKey)
  }
  
  def getUser: Option[String] = {
    cookies.get(User.key)
  }
  
  def clearUser() {
    clearCookie(User.key)
  }

  def storeUser(keyHash: String) {
    cookies.set(User.key, keyHash)
  }

  def getAndClearCookie(cookieName: String): String = {
    val cookie = cookies(cookieName)
    clearCookie(cookieName)
    cookie
  }

  def clearCookie(cookieName: String) {
    cookies.delete(cookieName)
  }
}
