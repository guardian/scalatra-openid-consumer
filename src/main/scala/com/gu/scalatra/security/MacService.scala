package com.gu.scalatra.security

import org.apache.commons.codec.binary.Hex
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.lang.StringUtils

abstract class MacService extends SecretKey {
  lazy val mac = Mac.getInstance("HmacSHA256")
  mac.init(secretKeySpec)
  
  def getMacForMessageAsHex(message: String) = {
    if (StringUtils.isBlank(message))
      None
    else
      Option(Hex.encodeHexString(getMacForMessage(message)))
  }
  
  def verifyMessageAgainstMac(message: String, macAsHexString: String) = {
    if (StringUtils.isBlank(message) || StringUtils.isBlank(macAsHexString))
      false
    else {
      getMacForMessageAsHex(message).map(_.equals(macAsHexString)).getOrElse(false)
    }
  }
  
  def getMacForMessage(message: String) = synchronized {
    mac.doFinal(message.getBytes())
  }
}

trait SecretKey {
  def secretKeySpec: SecretKeySpec
}
