package scalable.solutions

import org.apache.commons.codec.binary.Base64

import java.security.{PrivateKey, PublicKey}
import javax.crypto.Cipher

class Crypto(cipher: Cipher, privateKey: PrivateKey, publicKey: PublicKey, charsetName: String) {

  def encrypt(message: String): String = {
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    Base64.encodeBase64String(cipher.doFinal(message.getBytes(charsetName)))
  }

  def decrypt(message: String): String = {
    cipher.init(Cipher.DECRYPT_MODE, privateKey)
    new String(cipher.doFinal(Base64.decodeBase64(message)), charsetName)
  }
}

object Crypto {
  def apply(privateKeyFile: String, publicKeyFile: String,
            cipher: String = "RSA", charsetName: String = "UTF-8"): Crypto = {
    val keys = CryptoKeys(cipher)
    val publicKey = keys.getPublicKey(publicKeyFile, KeySource.FromResource)
    val privateKey = keys.getPrivateKey(privateKeyFile, KeySource.FromResource)
    new Crypto(Cipher.getInstance(cipher), privateKey, publicKey, charsetName)
  }
}

object CryptoApp extends App {
  val crypto = Crypto("private.key", "public.key")
  val text = "THE QUICK BROWN FOX JUMPED OVER THE LAZY DOG'S BACK 1234567890 !@#$%^&*()_+=-;:,.<>|\\[]{}/"
  val v = crypto.encrypt(text)
  println(v)
  println(crypto.decrypt(v))
}
