package com.gu.scalatra.security

import javax.crypto.spec.SecretKeySpec

case class KeyService(key: String) {
  def getSecretKeySpec = new SecretKeySpec(key.getBytes, "HmacSHA256")
}
