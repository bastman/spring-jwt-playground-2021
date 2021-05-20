package com.example.demo.util.jwt

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.springframework.security.oauth2.jose.jws.MacAlgorithm
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class JwtHS256(private val secret: String) {
    private val secretKey: SecretKey = secretKey(secret = secret)
    private val signerMAC: JWSSigner = MACSigner(secretKey)
    private val jwsAlgorithm: JWSAlgorithm = JWSAlgorithm.HS256
    private val macAlgorithm: MacAlgorithm = MacAlgorithm.HS256

    private fun secretKey(secret: String): SecretKey {
        val key: ByteArray = secret.toByteArray(Charsets.UTF_8)
        return SecretKeySpec(key, 0, key.size, "HMAC")
    }

    fun jwsHeader(block: JWSHeader.Builder.() -> Unit): JWSHeader = JWSHeader.Builder(jwsAlgorithm)
        .apply(block)
        .build()

    fun signedJwt(header: JWSHeader, claimsSet: JWTClaimsSet): SignedJWT {
        val signedJWT = SignedJWT(header, claimsSet)
        signedJWT.sign(signerMAC)
        return signedJWT
    }

    fun jwtDecoder(block: NimbusJwtDecoder.SecretKeyJwtDecoderBuilder.() -> Unit): NimbusJwtDecoder = NimbusJwtDecoder
        .withSecretKey(secretKey)
        .macAlgorithm(macAlgorithm)
        .apply(block)
        .build()

}
