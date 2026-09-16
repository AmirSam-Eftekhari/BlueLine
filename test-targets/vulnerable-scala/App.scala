import java.io.ObjectInputStream
import java.security.MessageDigest

object App {
  val apiKey: String = "sk_live_abcdEFGH12345678"

  def loadSession(data: java.io.InputStream): Any = {
    val ois = new ObjectInputStream(data)
    ois.readObject()
  }

  def weakHash(input: String): Array[Byte] = {
    val md = MessageDigest.getInstance("MD5")
    md.digest(input.getBytes)
  }

  def buildQuery(table: String): String = {
    s"SELECT * FROM $table WHERE active=1"
  }

  def parseArg(args: Array[String]): Int = {
    args(0).toInt
  }

  def runShell(cmd: String): String = {
    import scala.sys.process._
    cmd.!!
  }

  def genToken(): Int = {
    scala.util.Random().nextInt()
  }

  def main(args: Array[String]): Unit = {
    val first = args(0).get
    println(first)
  }
}
