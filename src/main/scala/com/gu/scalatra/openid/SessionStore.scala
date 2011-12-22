package com.gu.scalatra.openid

import collection.mutable.ConcurrentMap
import java.util.concurrent.ConcurrentHashMap
import collection.JavaConversions._

trait SessionStore {

  def isSessionAuthenticated(sessionId: String): Boolean

  def invalidate(sessionId: String): Unit

  def saveUser(sessionId: String, user: User): Unit

  def getUser(sessionId: String): Option[User]

}

trait InMemorySessionStore extends SessionStore {

  private val sessionAuth: ConcurrentMap[String, User] = new ConcurrentHashMap[String, User]()

  def isSessionAuthenticated(sessionId: String) = sessionAuth.get(sessionId) != None

  def invalidate(sessionId: String) = sessionAuth -= sessionId

  def saveUser(sessionId: String, user: User) = sessionAuth += (sessionId -> user)

  def getUser(sessionId: String) = sessionAuth.get(sessionId)

}