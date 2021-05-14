package com.example.demo.config.security

import com.example.demo.util.jwt.*
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

        // custom
        "/token/**"
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

    private fun jwtDecoder(): JwtDecoder {
        val jwtDecoder: NimbusJwtDecoder = SymmetricSignedJwt.HS256(secret = JWT_FAKE_SECRET)
            .jwtDecoder()
        jwtDecoder.setJwtValidator(jwtValidator())

        return jwtDecoder
    }

    private fun jwtValidator(): DelegatingOAuth2TokenValidator<Jwt> {
        val audiencesExpectedOneOf: List<String> = listOf("myaudience-1", "myaudience-2")
        val issuersExpectedOneOf: List<String> = listOf(
            "https://my-issuer-1.local",
            "https://my-issuer-2.local"
        )

        val defaultValidator: OAuth2TokenValidator<Jwt> = JwtValidators.createDefault()
        val issuerValidator: OAuth2TokenValidator<Jwt> = jwtIssuerClaimValidator(acceptIssuers = issuersExpectedOneOf)
            .toOAuth2TokenValidator()
        val audienceValidator: OAuth2TokenValidator<Jwt> =
            jwtAudienceClaimValidator(acceptAudiences = audiencesExpectedOneOf)
                .toOAuth2TokenValidator()

        return jwtCompoundOAuth2TokenValidator(
            defaultValidator, issuerValidator, audienceValidator
        )
    }


}
