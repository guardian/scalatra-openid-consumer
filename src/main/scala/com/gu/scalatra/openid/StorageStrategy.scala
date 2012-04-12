package com.gu.scalatra.openid

import com.gu.scalatra.security.{SecretKey, KeyService, MacService}
import org.scalatra.{CookieOptions, CookieSupport, ScalatraKernel}

trait StorageStrategy {
  lazy val redirectToKey = "redirectTo"

  def storeRedirectToUri(url: String)
  def getRedirectToUri: String
  def clearRedirectToUrl() { clearKey(redirectToKey) }

  def storeUser(user: User)
  def getUser: Option[User]
  def clearUser() { clearKey(User.key) }

  def clearKey(keyName: String)
}

trait CookieStorageStrategy extends StorageStrategy with ScalatraKernel with CookieSupport {

  val secretKey: String
  lazy val macService = new MacService with SecretKey {def secretKeySpec = new KeyService(secretKey).getSecretKeySpec}

  lazy val hashSeparator= ">>"
  lazy val userCookieRegEx = "^^([\\w\\W]*)>>([\\w\\W]*)$".r

  def storeRedirectToUri(url: String) { cookies.set(redirectToKey, url) }

  def getRedirectToUri = cookies(redirectToKey)

  def storeUser(user: User) {
    val value = user.asDelimitedString
    val hash = macService.getMacForMessageAsHex(value).get
    val signedUserData = value + hashSeparator + hash

    cookies.set(User.key, signedUserData)
  }

  def getUser = cookies.get(User.key).flatMap { cd =>
    cd match {
      case userCookieRegEx(userValue, hash) if macService.verifyMessageAgainstMac(userValue, hash) => Some(User(userValue))
      case _ => {
        clearKey(User.key)
        None
      }
    }
  }

  // set cookie rather than delete cookie via cookies.delete to work round bug in scalatra 2.0.X
  def clearKey(keyName: String) {cookies.set(keyName, "")(cookieOptions.copy(maxAge = 0)) }

}

trait SessionStorageStrategy extends StorageStrategy with ScalatraKernel {

  def storeRedirectToUri(url: String) { session.setAttribute(redirectToKey, url) }

  def getRedirectToUri = session.getAttribute(redirectToKey).asInstanceOf[String]

  def storeUser(user: User) { session.setAttribute(User.key, user) }

  def getUser = Option(session.getAttribute(User.key).asInstanceOf[User])

  def clearKey(keyName: String) { session.removeAttribute(keyName) }
}
