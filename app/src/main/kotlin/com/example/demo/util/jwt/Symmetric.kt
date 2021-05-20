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

object SymmetricSignedJwt {

    fun secretKey(secret: String): SecretKey {
        val key: ByteArray = secret.toByteArray(Charsets.UTF_8)
        return SecretKeySpec(key, 0, key.size, "HMAC")
    }

    class HS256(private val secret: String) {
        private val secretKey: SecretKey = secretKey(secret = secret)
        private val signerMAC: JWSSigner = MACSigner(secretKey)
        private val jwsAlgorithm: JWSAlgorithm = JWSAlgorithm.HS256
        private val macAlgorithm: MacAlgorithm = MacAlgorithm.HS256

        fun jwsHeader(block: JwsHeaderBuilderInit? = null): JWSHeader {
            return JWSHeader.Builder(jwsAlgorithm)
                .let {
                    if (block != null) {
                        it.apply(block)
                    }
                    it
                }
                .build()
        }

        fun signedJwt(header: JWSHeader, claimsSet: JWTClaimsSet): SignedJWT {
            val signedJWT = SignedJWT(header, claimsSet)
            signedJWT.sign(signerMAC)
            return signedJWT
        }

        fun jwtDecoder(block: JwtDecoderBuilder? = null): NimbusJwtDecoder {
            return NimbusJwtDecoder
                .withSecretKey(secretKey)
                .macAlgorithm(macAlgorithm)
                .let {
                    if (block != null) {
                        it.apply(block)
                    }
                    it
                }
                .build()
        }
    }

}

private typealias JwsHeaderBuilderInit = JWSHeader.Builder.() -> Unit
private typealias JwtDecoderBuilder = NimbusJwtDecoder.SecretKeyJwtDecoderBuilder.() -> Unit


