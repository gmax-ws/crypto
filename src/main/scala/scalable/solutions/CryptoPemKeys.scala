package scalable.solutions

import com.typesafe.config.ConfigFactory
import org.bouncycastle.util.encoders.Base64
import scalable.solutions.KeySource.KeySource

import java.nio.file.{Files, Path, Paths}
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.security.{KeyFactory, PrivateKey, PublicKey}
import scala.jdk.CollectionConverters.CollectionHasAsScala

object KeySource extends Enumeration {
  type KeySource = Value
  val FromFile, FromResource, FromConfig = Value
}

trait CryptoPemData {

  import scalable.solutions.KeySource._

  private val config = ConfigFactory.load

  private def getBytesFromConfig(key: String) = {
    val data = config.getString(key)
    val lines = data.split("\n").tail.dropRight(1).mkString("")
    Base64.decode(lines.getBytes("UTF-8"))
  }

  private def getBytesFromPath(path: Path) = {
    val data = Files.readAllLines(path).asScala
    val lines = data.tail.dropRight(1).mkString("")
    Base64.decode(lines.getBytes("UTF-8"))
  }

  private def getBytesFromFile(filename: String) = {
    getBytesFromPath(Paths.get(filename))
  }

  private def getBytesFromResource(resource: String) = {
    val path = Paths.get(Thread.currentThread.getContextClassLoader.getResource(resource).toURI)
    getBytesFromPath(path)
  }

  protected def getBytes(key: String, keySource: KeySource): Array[Byte] = {
    keySource match {
      case FromFile => getBytesFromFile(key)
      case FromResource => getBytesFromResource(key)
      case FromConfig => getBytesFromConfig(key)
      case _ => Array.empty[Byte]
    }
  }
}

class CryptoPemKeys(factory: KeyFactory) extends CryptoPemData {

  def getPrivateKey(key: String, keySource: KeySource): PrivateKey = {
    val keyBytes = getBytes(key, keySource)
    val spec = new PKCS8EncodedKeySpec(keyBytes)
    factory.generatePrivate(spec)
  }

  def getPublicKey(key: String, keySource: KeySource): PublicKey = {
    val keyBytes = getBytes(key, keySource)
    val spec = new X509EncodedKeySpec(keyBytes)
    factory.generatePublic(spec)
  }
}

object CryptoPemKeys {
  def apply(cipher: String = "RSA") =
    new CryptoPemKeys(KeyFactory.getInstance(cipher))
}

object TestPem extends App {

  import scalable.solutions.KeySource._

  val pem = CryptoPemKeys()
  println(pem.getPrivateKey("keys.privateKey", FromConfig))
  println(pem.getPublicKey("keys.publicKey", FromConfig))
}