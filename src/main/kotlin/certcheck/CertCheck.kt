package certcheck

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.arguments.multiple
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

fun loadCert(certFile: File): X509Certificate {
    FileInputStream(certFile).use({ certStream ->
        val cf = CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(certStream) as X509Certificate
    })

}

fun checkCertPath(cert: X509Certificate, authType: String) {
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    tmf.init(null as KeyStore?)
    val trustManager = tmf.trustManagers.first()!! as X509TrustManager
    trustManager.checkServerTrusted(arrayOf(cert), authType)
}


class CheckCerts : CliktCommand(name = "checkcert") {
    val verbose: Boolean by option(help = "enable verbose mode").flag()
    val certs: List<String> by argument(help = "X.509 cert filenames").multiple()
    val authType: String by option(help = "Auth type (default is RSA)").default("RSA")
    override fun run() {
        var anyFailed = false

        for (certPath in certs) {
            print("Checking ${certPath}: ")
            val certFile = File(certPath)
            if (!certFile.exists()) {
                anyFailed = true
                println("missing")
                continue
            }
            if (!certFile.isFile) {
                anyFailed = true
                println("not a regular file")
                continue
            }
            try {
                checkCertPath(loadCert(certFile), authType)
                println("✓ ok")
            } catch (e: CertificateException) {
                anyFailed = true
                if (verbose) {
                    println("✗ (failed) - ${e.message}")
                } else {
                    println("✗ (failed)")
                }
            }
        }
        if (anyFailed) {
            System.exit(1)
        }
    }

}

fun main(args: Array<String>) = CheckCerts().main(args)