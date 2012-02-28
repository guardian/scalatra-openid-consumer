package com.gu.scalatra.openid

import org.scalatra.{CookieSupport, ScalatraKernel}

trait StorageStrategy {
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

trait CookieStorageStrategy extends StorageStrategy with ScalatraKernel with CookieSupport {
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

trait SessionStorageStrategy extends StorageStrategy with ScalatraKernel {
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
