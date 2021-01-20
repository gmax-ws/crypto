package scalable.solutions

import scalable.solutions.KeySource.KeySource

import java.nio.file.{Files, Paths}
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.security.{KeyFactory, PrivateKey, PublicKey}

trait CryptoKeysData {

  import scalable.solutions.KeySource._

  private def getBytesFromFile(filename: String) = {
    Files.readAllBytes(Paths.get(filename))
  }

  private def getBytesFromResource(resource: String) = {
    val path = Paths.get(Thread.currentThread.getContextClassLoader.getResource(resource).toURI)
    Files.readAllBytes(path)
  }

  protected def getBytes(key: String, keySource: KeySource): Array[Byte] = {
    keySource match {
      case FromFile => getBytesFromFile(key)
      case FromResource => getBytesFromResource(key)
      case _ => Array.empty[Byte]
    }
  }
}

class CryptoKeys(factory: KeyFactory) extends CryptoKeysData {

  def getPrivateKey(filename: String, keySource: KeySource): PrivateKey = {
    val keyBytes = getBytes(filename, keySource)
    val spec = new PKCS8EncodedKeySpec(keyBytes)
    factory.generatePrivate(spec)
  }

  def getPublicKey(filename: String, keySource: KeySource): PublicKey = {
    val keyBytes = getBytes(filename, keySource)
    val spec = new X509EncodedKeySpec(keyBytes)
    factory.generatePublic(spec)
  }
}

object CryptoKeys {
  def apply(cipher: String = "RSA") =
    new CryptoKeys(KeyFactory.getInstance(cipher))
}