import java.io.ObjectInputStream
import java.security.MessageDigest
import javax.crypto.Cipher

val apiKey: String = "sk_live_abcdEFGH12345678"

fun runCommand(userInput: String) {
    Runtime.getRuntime().exec("echo $userInput")
}

fun loadSession(data: java.io.InputStream) {
    val ois = ObjectInputStream(data)
    ois.readObject()
}

fun weakHash(input: String): ByteArray {
    val md = MessageDigest.getInstance("MD5")
    return md.digest(input.toByteArray())
}

fun weakEncrypt(data: ByteArray): ByteArray {
    val c = Cipher.getInstance("DES")
    return c.doFinal(data)
}

fun runQuery(table: String): String {
    return "SELECT * FROM ${table} WHERE active=1"
}

fun parseArg(args: Array<String>): Int {
    return args[0]!!.toInt()
}
