package com.example.demo.config.security

import com.example.demo.util.jwt.SymmetricSignedJwt
import com.example.demo.util.jwt.expirationTime
import com.example.demo.util.jwt.issueTime
import com.example.demo.util.jwt.jwtClaimSet
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.SignedJWT
import mu.KLogging
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
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
            .oauth2ResourceServer { it.jwt() }
            .build()
    }

    @Bean
    fun jwtDecoder(): JwtDecoder {
        genToken()
        return SymmetricSignedJwt.HS256(secret = JWT_FAKE_SECRET).jwtDecoder()
    }

    fun genToken() {
        val hs256 = SymmetricSignedJwt.HS256(secret = JWT_FAKE_SECRET)
        val header: JWSHeader = hs256.jwsHeader { keyID("one") }
        val claimsSet = jwtClaimSet {
            subject("test-subject")
            issueTime(Instant.now())
            expirationTime(Instant.now() + Duration.ofDays(1))
        }

        val signedJwt: SignedJWT = hs256.signedJwt(header, claimsSet)
        val signedJwtSerialized: String = signedJwt.serialize()
        logger.info { "signed fake jwt: $signedJwtSerialized" }

        val decoder: NimbusJwtDecoder = hs256.jwtDecoder()
        val decoded: Jwt = decoder.decode(signedJwtSerialized)
        val decodedSubject: String = decoded.subject
        if (decodedSubject != "test-subject") {
            error("wrong subject")
        }

    }


    /*
    @Bean
    fun jwtDecoder(
        properties: OAuth2ResourceServerProperties,
        @Value("\${auth0.audience}") audience: String?
    ): JwtDecoder? {
        // By default, Spring Security does not validate the "aud" claim of the token, to ensure that this token is
        // indeed intended for our app. Adding our own validator is easy to do:
        val issuerUri = properties.jwt.issuerUri
        val jwtDecoder = JwtDecoders.fromOidcIssuerLocation(issuerUri) as NimbusJwtDecoder
        val audienceValidator: OAuth2TokenValidator<Jwt> = AudienceValidator.of(audience)
        val withIssuer: OAuth2TokenValidator<Jwt> = JwtValidators.createDefaultWithIssuer(issuerUri)
        val withAudience: OAuth2TokenValidator<Jwt> = DelegatingOAuth2TokenValidator<T>(withIssuer, audienceValidator)
        jwtDecoder.setJwtValidator(withAudience)
        return jwtDecoder
    }

     */
}
