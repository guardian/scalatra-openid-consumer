package com.gu.scalatra.openid

import org.openid4java.consumer.ConsumerManager
import org.openid4java.message.{AuthSuccess, ParameterList}
import org.openid4java.message.ax.{FetchResponse, AxMessage, FetchRequest}
import com.gu.scalatra.security.{KeyService, MacService, SecretKey}
import org.scalatra.CookieSupport._
import org.scalatra.ScalatraKernel._
import org.scalatra.CookieOptions._
import org.scalatra.{CookieOptions, CookieSupport, ScalatraKernel}

trait OpenIdConsumer extends ScalatraKernel with UserAuthorisation with OpenIdConsumerSupport {

  val authenticationReturnUri: String
  val authenticationReturnPath: String
  val protectedPaths: List[String]
  val discoveryEndpoint: String
  val logoutPath: String
  val logoutRedirect: String
  val secretKey: String

  lazy val discovered = "discovered"
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
    redirectToUri(request.getRequestURI)
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
      getUserKey match {
        case Some(userKeyHash) => {
          userRegEx.split(userKeyHash) match {
            case userRegEx(userValue, hash) => {
              if (!macService.verifyMessageAgainstMac(userValue + hashSeparator, hash)) {
                clearUserKey()
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
        if (isUserAuthorised(user))
          session.setAttribute(User.key, user)  // Store the authorised user so it can be used by the app
        else {
          clearUser()
          halt(status = 403, reason = "Sorry, you are not authorised")
        }
        val value = userKeyPattern.format(userEmail, userFirstName, userLastName)
        macService.getMacForMessageAsHex(value) foreach { hash =>
          storeUserKey(value + hash)
          redirect(getRedirectToUri)
        }
      }
    } else
      halt(status = 403, reason = "Could not verify authentication with provider")
  }

  get(logoutPath) {
    session.invalidate()
    clearUserKey()
    clearUser()
    redirect(logoutRedirect)
  }

}

trait OpenIdConsumerSupport {
  lazy val redirectToKey = "redirectTo"
  lazy val userKeyHash = "userKeyHash"

  def redirectToUri(url: String)

  def getRedirectToUri: String

  def getUserKey: Option[String]

  def clearUserKey() {
    getAndClearUserKey(userKeyHash)
  }

  def clearUser() {
    getAndClearUserKey(User.key)
  }

  def storeUserKey(keyHash: String)

  def getAndClearUserKey(keyName: String): String
}

trait OpenIdConsumerCookieSupport extends OpenIdConsumerSupport with ScalatraKernel with CookieSupport {
  def redirectToUri(url: String) {
    cookies.set(redirectToKey, request.getRequestURI)
  }

  def getRedirectToUri: String = {
    getAndClearUserKey(redirectToKey)
  }
  
  def getUserKey: Option[String] = {
    cookies.get(userKeyHash)
  }

  def storeUserKey(keyHash: String) {
    cookies.set(userKeyHash, keyHash)
  }

  def getAndClearUserKey(keyName: String): String = {
    val cookie = cookies(keyName)
    clearCookie(keyName)
    cookie
  }

  private def clearCookie(keyName: String) {
    cookies.delete(keyName)
  }
}

trait OpenIdConsumerSessionSupport extends OpenIdConsumerSupport with ScalatraKernel {
  def redirectToUri(url: String) {
    session.setAttribute(redirectToKey, url)
  }

  def getRedirectToUri: String = {
    session.getAttribute(redirectToKey).asInstanceOf[String]
  }

  def getUserKey: Option[String] = {
    Option(session.getAttribute(userKeyHash).asInstanceOf[String])
  }

  def storeUserKey(keyHash: String) {
    session.setAttribute(userKeyHash, keyHash)
  }

  def getAndClearUserKey(keyName: String): String = {
    val user = session.getAttribute(keyName).asInstanceOf[String]
    session.invalidate()
    user
  }

}
