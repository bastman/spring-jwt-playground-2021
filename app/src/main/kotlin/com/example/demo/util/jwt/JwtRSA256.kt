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

/**
 * see: https://www.baeldung.com/spring-security-oauth-auth-server
 */


class JwtRSA256(
    private val rsaKey: RSAKey
) {
    private val jwsAlgorithm: JWSAlgorithm = JWSAlgorithm.RS256
    private val jwsSigner: RSASSASigner = RSASSASigner(rsaKey)

    fun jwsHeader(block: JWSHeader.Builder.() -> Unit): JWSHeader = JWSHeader.Builder(jwsAlgorithm)
        .apply {
            this.keyID(rsaKey.keyID)
            this.type(JOSEObjectType.JWT)
        }
        .apply(block)
        .build()

    fun signedJwt(header: JWSHeader, claimsSet: JWTClaimsSet): SignedJWT {
        val signedJWT = SignedJWT(header, claimsSet)
        signedJWT.sign(jwsSigner)
        return signedJWT
    }

    fun jwtDecoder(block: NimbusJwtDecoder.PublicKeyJwtDecoderBuilder.() -> Unit): NimbusJwtDecoder = NimbusJwtDecoder
        .withPublicKey(rsaKey.toRSAPublicKey())
        .apply(block)
        .build()

    fun jwkSource(rsaKey: RSAKey): JWKSource<SecurityContext> {
        val jwkSet = JWKSet(rsaKey)
        return JWKSource<SecurityContext> { jwkSelector: JWKSelector, _: SecurityContext ->
            jwkSelector.select(
                jwkSet
            )
        }
    }

    fun toPublicJWKSetJSONString(): String = rsaKey.toPublicJWKSetJSONString()

    fun toRSAKeyB64String(): String = rsaKey.toRSAKeyB64String()

    companion object {
        fun of(rsaKey: RSAKey): JwtRSA256 = JwtRSA256(rsaKey)
        fun ofRSAKeyB64String(rsaKeyB64: String): JwtRSA256 {
            val rsaKey: RSAKey = RSAKeyFactory.rsaKeyOfB64String(rsaKeyB64)
            return JwtRSA256(rsaKey)
        }
    }
}
