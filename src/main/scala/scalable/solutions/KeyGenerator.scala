package scalable.solutions

import com.google.common.base.Splitter
import org.bouncycastle.util.encoders.Base64

import java.io.FileOutputStream
import java.security._
import scala.jdk.CollectionConverters.IterableHasAsScala
import scala.util.Using

class KeyGenerator(cipher: String, keySize: Int) {
  private def beg(n: String) = s"-----BEGIN ${n.toUpperCase} KEY-----"
  private def end(n: String) = s"-----END ${n.toUpperCase} KEY-----"

  private val pair = generateKeys(keySize)

  private def generateKeys(keySize: Int): KeyPair = {
    val keyGen = KeyPairGenerator.getInstance(cipher)
    keyGen.initialize(keySize, SecureRandom.getInstance("SHA1PRNG", "SUN"))
    keyGen.generateKeyPair
  }

  private def encodePem(key: Key, beg: String, end: String) = {
    val base64encoded = Base64.toBase64String(key.getEncoded)
    val lines = Splitter.fixedLength(64).split(base64encoded)
    (List(beg) ++ lines.asScala ++ List(end)).mkString("\n")
  }

  def getPem(isPublic: Boolean): String = {
    if (isPublic)
      encodePem(pair.getPublic, beg("public"), end("public"))
    else
      encodePem(pair.getPrivate, beg("private"), end("private"))
  }

  def getKey(filename: String, isPublic: Boolean): Either[Throwable, Unit] = {
    val data = if (isPublic) pair.getPublic.getEncoded else pair.getPrivate.getEncoded
    Using(new FileOutputStream(filename)) { output =>
      output.write(data)
    }.toEither
  }
}

object KeyGenerator {
  def apply(cipher: String = "RSA", keySize: Int = 1024) = new KeyGenerator(cipher, keySize)
}

object Test {
  def main(args: Array[String]): Unit = {
    val gen = KeyGenerator()
    println(gen.getPem(isPublic = true))
    println(gen.getPem(isPublic = false))

    gen.getKey("public.key", isPublic = true)
    gen.getKey("private.key", isPublic = false)
  }
}
