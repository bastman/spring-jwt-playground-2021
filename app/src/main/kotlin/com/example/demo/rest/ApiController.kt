package com.example.demo.rest

import com.example.demo.config.security.SecurityConfig
import com.example.demo.util.jwt.*
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import mu.KLogging
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import springfox.documentation.annotations.ApiIgnore
import java.time.Duration
import java.time.Instant

@RestController
class ApiController {
    companion object : KLogging()

    @GetMapping("/api/me")
    fun me(
        @ApiIgnore authentication: JwtAuthenticationToken
        // ,@ApiIgnore @AuthenticationPrincipal  oidcUser: OidcUser
    ): Any {

        val jwt: Jwt = authentication.token

        return mapOf(
            "foo" to "bar",
            "auth" to mapOf(
                "name" to authentication.name,
                "authorities" to authentication.authorities,
                "tokenAttributes" to authentication.tokenAttributes,
                "token" to authentication.token as Jwt, // Jwt
                "principal" to authentication.principal as Jwt, // Jwt
                "credentials" to authentication.credentials as Jwt, // Jwt
                "details" to authentication.details
            )
        )
    }

    @PostMapping("/token/example-token")
    fun generateExampleToken(): Any? {
        val claimsSet: JWTClaimsSet = jwtClaimSet {
            subject("test-subject")
            issueTime(Instant.now())
            expirationTime(Instant.now() + Duration.ofDays(1))
            issuer("https://my-issuer-1.local")
            audience(listOf("myaudience-1", "myaudience-2"))
        }

        val hs256 = SymmetricSignedJwt.HS256(secret = SecurityConfig.JWT_FAKE_SECRET)
        val header: JWSHeader = hs256.jwsHeader { keyID("my-example-key-id") }
        val signedJwt: SignedJWT = hs256.signedJwt(header, claimsSet)
        val signedJwtSerialized: String = signedJwt.serialize()

        logger.info { "signed fake jwt ... $signedJwtSerialized" }
        logger.info { "=====================" }
        logger.info { "Bearer $signedJwtSerialized" }
        logger.info { "=====================" }

        val decoder: NimbusJwtDecoder = hs256.jwtDecoder()
        val decoded: Jwt = decoder.decode(signedJwtSerialized)
        val decodedSubject: String = decoded.subject
        if (decodedSubject != "test-subject") {
            error("wrong subject")
        }

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
