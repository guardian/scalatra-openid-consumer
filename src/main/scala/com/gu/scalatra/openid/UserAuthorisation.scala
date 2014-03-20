package com.gu.scalatra.openid

trait UserAuthorisation {

  def isUserAuthorised(user: User): AuthorisationResponse

}

class AlwaysAllowUserAuthorisation extends UserAuthorisation {

  def isUserAuthorised(user: User) = Authorised

}

sealed trait AuthorisationResponse
case object Authorised extends AuthorisationResponse
case class Refused(errorKey: String) extends AuthorisationResponse
