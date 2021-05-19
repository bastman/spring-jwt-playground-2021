package com.example.demo.util.jwt

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
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

    fun jwsHeader(rsaKey: RSAKey, block: JWSHeader.Builder.() -> Unit): JWSHeader {
        val jwsAlgorithm = JWSAlgorithm.RS256
        return JWSHeader.Builder(jwsAlgorithm)
            .apply {
                this.keyID(rsaKey.keyID)
                this.type(JOSEObjectType.JWT)
            }
            .apply(block)
            .build()
    }

    fun jwsSigner(rsaKey: RSAKey): RSASSASigner = RSASSASigner(rsaKey)

    fun signedJwt(rsaSigner: RSASSASigner, header: JWSHeader, claimsSet: JWTClaimsSet): SignedJWT {
        val signedJWT = SignedJWT(header, claimsSet)
        signedJWT.sign(rsaSigner)
        return signedJWT
    }

    fun jwtDecoder(rsaKey: RSAKey): NimbusJwtDecoder {
        return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey())
            .build()

    }


    fun jwkSource(rsaKey: RSAKey): JWKSource<SecurityContext> {
        val jwkSet = JWKSet(rsaKey)

        return JWKSource<SecurityContext> { jwkSelector: JWKSelector, _: SecurityContext ->
            jwkSelector.select(
                jwkSet
            )
        }
    }


    fun getPublicJWKSasJsonString(rsaKey: RSAKey): String {
        // exposes public keys only
        val jwkSet = JWKSet(rsaKey)
        return jwkSet.toPublicJWKSet().toJSONObject(true).toJSONString()
    }

    fun rsaKeyFromJsonStringB64(rsaKeyB64: String): RSAKey {
        val rsaKeyJson: String = Base64.getDecoder().decode(rsaKeyB64).decodeToString()
        return RSAKey.parse(rsaKeyJson)
    }

    /*

     */

}
