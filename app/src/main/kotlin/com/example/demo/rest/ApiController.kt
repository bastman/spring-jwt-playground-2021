package com.example.demo.rest

import com.example.demo.config.security.SecurityConfig
import com.example.demo.util.jwt.*
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import java.time.Duration
import java.time.Instant

@RestController
class ApiController {

    @GetMapping("/api/me")
    fun me(): Any {
        return mapOf(
            "foo" to "bar"
        )
    }

    @PostMapping("/token/example-token")
    fun generateExampleToken(): Any? {
        val claimsSet: JWTClaimsSet = jwtClaimSet {
            subject("test-subject")
            issueTime(Instant.now())
            expirationTime(Instant.now() + Duration.ofDays(1))
            issuer("my-issuer-1")
            audience(listOf("myaudience-1", "myaudience-2"))
        }

        val hs256 = SymmetricSignedJwt.HS256(secret = SecurityConfig.JWT_FAKE_SECRET)
        val header: JWSHeader = hs256.jwsHeader { keyID("my-example-key-id") }
        val signedJwt: SignedJWT = hs256.signedJwt(header, claimsSet)
        val signedJwtSerialized: String = signedJwt.serialize()

        return mapOf(
            "token" to "Bearer $signedJwtSerialized",
            "data" to mapOf(
                "jwtHeader" to header,
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

        val hs256 = SymmetricSignedJwt.HS256(secret = SecurityConfig.JWT_FAKE_SECRET)
        val header: JWSHeader = hs256.jwsHeader { keyID("my-example-key-id") }
        val signedJwt: SignedJWT = hs256.signedJwt(header, claimsSet)
        val signedJwtSerialized: String = signedJwt.serialize()

        return mapOf(
            "token" to "Bearer $signedJwtSerialized",
            "data" to mapOf(
                "jwtHeader" to header,
                "jwtClaimsSet" to claimsSet,
                "signedJwt" to signedJwt
            )
        )
    }


}
