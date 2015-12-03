package com.enalta.alkindi

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMReader
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyPair
import java.security.KeyStore
import java.security.Security
import java.security.cert.X509Certificate
import javax.net.SocketFactory
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

fun socketFactory(caCert: String, certFile: String, keyFile: String, tlsVersion: String = "TLSv1.2"): SocketFactory {
    Security.addProvider(BouncyCastleProvider())

    val password = "".toCharArray()

    val trustManagerFactory =
            trustManagerFactory(keyStore(x509Certificate(caCert), true, keyFile, null))

    val keyManagerFactory =
            keyManagerFactory(keyStore(x509Certificate(certFile), false, keyFile, password), password)

    val context = SSLContext.getInstance(tlsVersion).apply {
        init(keyManagerFactory.keyManagers, trustManagerFactory.trustManagers, null)
    }

    return context.socketFactory
}

fun keyStore(cert: X509Certificate, isCa: Boolean, keyFile: String, password: CharArray?) =
        KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry(if (isCa) "ca-certificate" else "certificate", cert)
            password?.let { setKeyEntry("private-key", keyPair(keyFile).private, it, arrayOf(cert)) }
        }

fun trustManagerFactory(keyStore: KeyStore) =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
            init(keyStore)
        }

fun keyManagerFactory(keyStore: KeyStore, password: CharArray) =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
            init(keyStore, password)
        }

fun pemObject(pemPath: String): Any? {
    var reader: PEMReader? = null

    try {
        reader = PEMReader(InputStreamReader(ByteArrayInputStream(Files.readAllBytes(Paths.get(pemPath)))), { "".toCharArray() })
        return reader.readObject()
    } catch (e: Exception) {
        e.printStackTrace()
        return null
    } finally {
        reader?.close()
    }
}

fun x509Certificate(pemPath: String) = pemObject(pemPath) as X509Certificate

fun keyPair(pemPath: String) = pemObject(pemPath) as KeyPair

