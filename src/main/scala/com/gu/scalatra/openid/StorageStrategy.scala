package com.gu.scalatra.openid

import com.gu.scalatra.security.{SecretKey, KeyService, MacService}
import org.scalatra.{Cookie, CookieOptions, CookieSupport, ScalatraKernel}
import org.apache.commons.codec.binary.Base64

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

object userCookie {
  lazy val userCookieRegEx = "^^([\\w\\W]*)>>([\\w\\W]*)$".r

  def unapply(cookieValue: String): Option[(String, String)] = cookieValue match {
    case userCookieRegEx(userValueBlob, hash) => Some((decode64(userValueBlob), hash))
    case _ => None
  }

  def decode64(data: String): String = new String(Base64.decodeBase64(data.getBytes("UTF-8")))
}

trait CookieStorageStrategy extends StorageStrategy with ScalatraKernel with CookieSupport {

  val secretKey: String
  lazy val macService = new MacService with SecretKey {def secretKeySpec = new KeyService(secretKey).getSecretKeySpec}

  lazy val hashSeparator= ">>"

  def storeRedirectToUri(url: String) { response.addHeader("Set-Cookie", Cookie(redirectToKey, url).toCookieString) }

  def getRedirectToUri = cookies(redirectToKey)

  def storeUser(user: User) {
    val value = user.asCookieData
    val hash = macService.getMacForMessageAsHex(value).get
    val signedUserData = encode64(value) + hashSeparator + hash

    response.addHeader("Set-Cookie", Cookie(User.key, signedUserData).toCookieString)
  }

  def getUser = cookies.get(User.key).flatMap { cd =>
    cd match {
      case userCookie(userValue, hash) if macService.verifyMessageAgainstMac(userValue, hash) => Some(User(userValue))
      case _ => {
        clearKey(User.key)
        None
      }
    }
  }

  // set cookie rather than delete cookie via cookies.delete to work round bug in scalatra 2.0.X
  def clearKey(keyName: String) {cookies.set(keyName, "")(cookieOptions.copy(maxAge = 0)) }

  // user data is base64'd in the cookie to avoid issues with character encoding
  def encode64(data: String): String = new String(Base64.encodeBase64(data.getBytes("UTF-8")))
}

trait SessionStorageStrategy extends StorageStrategy with ScalatraKernel {

  def storeRedirectToUri(url: String) { session.setAttribute(redirectToKey, url) }

  def getRedirectToUri = session.getAttribute(redirectToKey).asInstanceOf[String]

  def storeUser(user: User) { session.setAttribute(User.key, user) }

  def getUser = Option(session.getAttribute(User.key).asInstanceOf[User])

  def clearKey(keyName: String) { session.removeAttribute(keyName) }
}
