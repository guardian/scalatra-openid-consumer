package com.gu.scalatra.openid

case class User(email: String, firstName: String, lastName: String) {
  import User.delimitedUserPattern

  def asCookieData = delimitedUserPattern.format(email, firstName, lastName)
}

object User {
  lazy val key = User.getClass.getName
  lazy val delimitedUserPattern = "%s|%s|%s"

  def apply(delimitedString: String) = {
    val parts = delimitedString.split('|')
    new User(parts(0), parts(1), parts(2))
  }
}
