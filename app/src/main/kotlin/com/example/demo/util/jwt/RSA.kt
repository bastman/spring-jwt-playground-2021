package com.example.demo.util.jwt

import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*

/**
 * see: https://www.baeldung.com/spring-security-oauth-auth-server
 */
object RSA {
    fun generateKeyPair(): KeyPair {
        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        return keyPairGenerator.genKeyPair()
    }

    fun generateRSAKey(): RSAKey {
        val keyPair: KeyPair = generateKeyPair()
        val publicKey: RSAPublicKey = keyPair.public as RSAPublicKey
        val privateKey: RSAPrivateKey = keyPair.private as RSAPrivateKey
        return RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
    }

    fun jwkSource(): JWKSource<SecurityContext> {
        val rsaKey: RSAKey = generateRSAKey()
        val jwkSet = JWKSet(rsaKey)

        return JWKSource<SecurityContext> { jwkSelector: JWKSelector, _: SecurityContext ->
            jwkSelector.select(
                jwkSet
            )
        }
    }
}
