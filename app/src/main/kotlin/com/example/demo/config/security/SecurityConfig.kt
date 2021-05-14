package com.example.demo.config.security

import com.example.demo.util.jwt.*
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import mu.KLogging
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtValidators
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.web.SecurityFilterChain
import java.time.Duration
import java.time.Instant


/**
 * see: https://github.com/hantsy/spring-security-auth0-sample/blob/master/api/src/main/java/com/example/demo/config/SecurityConfig.java
 */

@Configuration
class SecurityConfig {
    companion object : KLogging() {
        val JWT_FAKE_SECRET = "foo - The secret length must be at least 256 bits"
    }

    private val endpointsFullyAuthenticated: List<String> = listOf("/api/**")
    private val endpointsUnsecured: List<String> = listOf(
        "/",
        "/info",

        // springfox-swagger2 (2.9.x)
        "/v2/api-docs",
        "/configuration/ui",
        "/swagger-resources/**",
        "/configuration/security",
        "/swagger-ui.html",
        "/webjars/**",
    )

    @Bean
    fun springWebFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            .httpBasic { it.disable() }
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .authorizeRequests {
                it
                    .antMatchers(*(endpointsUnsecured.toTypedArray())).permitAll()
                    .antMatchers(*(endpointsFullyAuthenticated.toTypedArray())).fullyAuthenticated()
                    .anyRequest().authenticated()
            }
            .oauth2ResourceServer { oauth2Conf ->
                oauth2Conf.jwt {
                    it.decoder(jwtDecoder())
                }
            }
            .build()
    }

    //@Bean
    private fun jwtDecoder(): JwtDecoder {
        genToken()
        val jwtDecoder: NimbusJwtDecoder = SymmetricSignedJwt.HS256(secret = JWT_FAKE_SECRET)
            .jwtDecoder()

        val defaultValidator: OAuth2TokenValidator<Jwt> = JwtValidators.createDefault()
        val audiencesExpectedOneOf: List<String> = listOf("myaudience-1", "myaudience-2")
        val issuersExpectedOneOf: List<String> = listOf("my-issuer-1", "my-issuer-2")
        val issuerValidator: OAuth2TokenValidator<Jwt> = jwtIssuerClaimValidator(acceptIssuers = issuersExpectedOneOf)
            .toOAuth2TokenValidator()
        val audienceValidator: OAuth2TokenValidator<Jwt> =
            jwtAudienceClaimValidator(acceptAudiences = audiencesExpectedOneOf)
                .toOAuth2TokenValidator()

        val compoundValidator: DelegatingOAuth2TokenValidator<Jwt> = jwtCompoundOAuth2TokenValidator(
            defaultValidator, issuerValidator, audienceValidator
        )
        jwtDecoder.setJwtValidator(compoundValidator)

        return jwtDecoder
    }

    fun genToken() {
        val hs256 = SymmetricSignedJwt.HS256(secret = JWT_FAKE_SECRET)
        val header: JWSHeader = hs256.jwsHeader { keyID("my-example-key-id") }
        val claimsSet: JWTClaimsSet = jwtClaimSet {
            subject("test-subject")
            issueTime(Instant.now())
            expirationTime(Instant.now() + Duration.ofDays(1))
        }

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

    }


}
