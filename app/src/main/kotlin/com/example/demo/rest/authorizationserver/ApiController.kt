package com.example.demo.rest.authorizationserver


import com.example.demo.config.security.jwt.resourceserver.MyAuthConfig
import com.example.demo.util.jwt.*
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import mu.KLogging
import net.minidev.json.JSONObject
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import java.time.Duration
import java.time.Instant
import java.util.*

@RestController
class FakeAuthorizationServerApiController(
    private val myAuthConfig: MyAuthConfig
) {
    companion object : KLogging()

    /**
     * authorization server
     * see: https://github.com/spring-projects-experimental/spring-authorization-server/blob/main/oauth2-authorization-server/src/main/java/org/springframework/security/oauth2/server/authorization/web/NimbusJwkSetEndpointFilter.java
     */
    @GetMapping("/.well-known/jwks.json")
    fun getJWKS(): Any? {
        return when (val it = myAuthConfig) {
            is MyAuthConfig.JwtFakeRSA256 -> it.rsaKey.toPublicJWKSetJSONString()
            else -> error("rsa authorization server - disabled")
        }
    }

    @PostMapping("/token/generate-rsa-keys")
    fun generateRSAKeys(): Any? {
        val newRSAKey = RSAKeyFactory.generateRSAKey()
        val pubKey = newRSAKey.toRSAPublicKey()
        val privKey = newRSAKey.toRSAPrivateKey()

        val jsonObject: JSONObject = newRSAKey.toJSONObject()
        val rsaKey2 = RSAKey.parse(jsonObject)
        val pubKey2 = rsaKey2.toRSAPublicKey()
        val privKey2 = rsaKey2.toRSAPrivateKey()
        println("====== pub key =====")
        println(pubKey2)
        println("====== priv key =====")
        println(privKey2)

        if (pubKey2 != pubKey) {
            error("pub key does not match")
        }
        if (privKey2 != privKey) {
            error("priv key does not match")
        }
        val rsaKeyJson: String = jsonObject.toJSONString()
        return mapOf(
            "rsaKeyB64" to Base64.getEncoder().encodeToString(rsaKeyJson.toByteArray()),
            "rsaKey" to jsonObject
        )
    }

    @PostMapping("/token/example-token")
    fun generateExampleToken(): Any? {
        val jwtIssuer: String = when (myAuthConfig) {
            is MyAuthConfig.JwtProd -> myAuthConfig.issuer
            is MyAuthConfig.JwtFakeHS256 -> myAuthConfig.issuer
            is MyAuthConfig.JwtFakeRSA256 -> myAuthConfig.issuer
        }
        val jwtAudience: String = when (myAuthConfig) {
            is MyAuthConfig.JwtProd -> myAuthConfig.audience
            is MyAuthConfig.JwtFakeHS256 -> myAuthConfig.audience
            is MyAuthConfig.JwtFakeRSA256 -> myAuthConfig.audience
        }

        val claimsSet: JWTClaimsSet = jwtClaimSet {
            subject("test-subject")
            issueTime(Instant.now())
            expirationTime(Instant.now() + Duration.ofDays(1))
            issuer(jwtIssuer)
            audience(listOf(jwtAudience, "myaudience-2"))
        }

        val signedJwt: SignedJWT = when (myAuthConfig) {
            is MyAuthConfig.JwtProd -> error("endpoint not enabled")
            is MyAuthConfig.JwtFakeHS256 -> signedJwtHS256(myAuthConfig.hs256Secret, claimsSet)
            is MyAuthConfig.JwtFakeRSA256 -> signedJwtRSA256(myAuthConfig.rsaKey, claimsSet)
        }
        val signedJwtSerialized: String = signedJwt.serialize()

        return mapOf(
            "token" to "Bearer $signedJwtSerialized",
            "data" to mapOf(
                "jwtClaimsSet" to claimsSet,
                "signedJwt" to signedJwt
            )
        )
    }

    @PostMapping("/token/sign-token")
    fun signToken(
        @RequestBody payload: Map<String, Any?>
    ): Any? {

        val claimsSet: JWTClaimsSet = jwtClaimSet {
            claims(payload)
            expirationTime(Instant.now() + Duration.ofDays(1))
        }

        val signedJwt: SignedJWT = when (myAuthConfig) {
            is MyAuthConfig.JwtProd -> error("endpoint not enabled")
            is MyAuthConfig.JwtFakeHS256 -> signedJwtHS256(myAuthConfig.hs256Secret, claimsSet)
            is MyAuthConfig.JwtFakeRSA256 -> signedJwtRSA256(myAuthConfig.rsaKey, claimsSet)
        }
        val signedJwtSerialized: String = signedJwt.serialize()

        return mapOf(
            "token" to "Bearer $signedJwtSerialized",
            "data" to mapOf(
                "jwtClaimsSet" to claimsSet,
                "signedJwt" to signedJwt
            )
        )
    }


    private fun signedJwtHS256(hs256Secret: String, claimsSet: JWTClaimsSet): SignedJWT {
        val hs256 = SymmetricSignedJwt.HS256(secret = hs256Secret)
        val header: JWSHeader = hs256.jwsHeader { keyID("my-example-key-id") }
        val signedJwt: SignedJWT = hs256.signedJwt(header, claimsSet)
        val signedJwtSerialized: String = signedJwt.serialize()

        logger.info { "signed fake jwt (HS256) ... $signedJwtSerialized" }
        logger.info { "=====================" }
        logger.info { "Bearer $signedJwtSerialized" }
        logger.info { "=====================" }

        // check decoding works ...
        val decoder: NimbusJwtDecoder = hs256.jwtDecoder()
        val decoded: Jwt = decoder.decode(signedJwtSerialized)

        return signedJwt
    }

    private fun signedJwtRSA256(rsaKey: RSAKey, claimsSet: JWTClaimsSet): SignedJWT {
        val rs = JwtRSA256(rsaKey)
        val header: JWSHeader = rs.jwsHeader() {}
        val signedJwt: SignedJWT = rs.signedJwt(header, claimsSet)
        val signedJwtSerialized: String = signedJwt.serialize()
        logger.info { "signed fake jwt (RSA256) ... $signedJwtSerialized" }
        logger.info { "=====================" }
        logger.info { "Bearer $signedJwtSerialized" }

        // check decoding works ...
        val decoder: NimbusJwtDecoder = rs.jwtDecoder() {}
        val decoded: Jwt = decoder.decode(signedJwtSerialized)
        logger.info { "decoding works. claims: ${decoded.claims}" }
        logger.info { "=====================" }
        return signedJwt
    }

}
