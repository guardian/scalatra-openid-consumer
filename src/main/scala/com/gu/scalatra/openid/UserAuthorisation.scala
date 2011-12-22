package com.gu.scalatra.openid

trait UserAuthorisation {

  def isUserAuthorised(user: User): Boolean

}

class AlwaysAllowUserAuthorisation extends UserAuthorisation {

  def isUserAuthorised(user: User) = true

}