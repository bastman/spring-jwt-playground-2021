package com.example.demo.config.security

import com.example.demo.config.security.jwt.MyAuthConfig
import com.example.demo.util.jwt.*
import mu.KLogging
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoders
import org.springframework.security.oauth2.jwt.JwtValidators
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.web.SecurityFilterChain


/**
 * see: https://github.com/hantsy/spring-security-auth0-sample/blob/master/api/src/main/java/com/example/demo/config/SecurityConfig.java
 */

@Configuration
class SecurityConfig(
    private val myAuthConfig: MyAuthConfig
) {
    companion object : KLogging()

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
            .oauth2ResourceServer { resourceServer(it, myAuthConfig) }
            .build()
    }

    private fun resourceServer(rs: OAuth2ResourceServerConfigurer<HttpSecurity?>, myAuthConfig: MyAuthConfig) {
        when (myAuthConfig) {
            is MyAuthConfig.JwtFake -> fakeAuthResourceServer(rs, myAuthConfig)
            is MyAuthConfig.JwtProd -> prodAuthResourceServer(rs, myAuthConfig)
        }.let { Unit }
    }

    private fun fakeAuthResourceServer(
        rs: OAuth2ResourceServerConfigurer<HttpSecurity?>,
        myAuthConfig: MyAuthConfig.JwtFake
    ) {
        rs.jwt {
            val validator = jwtValidator(
                acceptIssuers = listOf(myAuthConfig.issuer),
                acceptAudiences = listOf(myAuthConfig.audience)
            )
            val decoder = jwtDecoderFake(hs256Secret = myAuthConfig.hs256Secret)
            decoder.setJwtValidator(validator)
            it.decoder(decoder)
        }
    }

    private fun prodAuthResourceServer(
        rs: OAuth2ResourceServerConfigurer<HttpSecurity?>,
        authConfig: MyAuthConfig.JwtProd
    ) {
        rs.jwt {
            val validator = jwtValidator(
                acceptIssuers = listOf(authConfig.issuer),
                acceptAudiences = listOf(authConfig.audience)
            )
            val decoder = jwtDecoderProd(issuerUri = authConfig.issuer)
            decoder.setJwtValidator(validator)
            it.decoder(decoder)
        }
    }

    private fun jwtDecoderProd(issuerUri: String): NimbusJwtDecoder {
        return JwtDecoders.fromIssuerLocation(issuerUri) as NimbusJwtDecoder
    }


    private fun jwtDecoderFake(hs256Secret: String): NimbusJwtDecoder {
        return SymmetricSignedJwt.HS256(secret = hs256Secret)
            .jwtDecoder()
    }

    private fun jwtValidator(
        acceptIssuers: List<String>, acceptAudiences: List<String>
    ): DelegatingOAuth2TokenValidator<Jwt> {
        val defaultValidator: OAuth2TokenValidator<Jwt> = JwtValidators.createDefault()
        val issuerValidator: OAuth2TokenValidator<Jwt> = jwtIssuerClaimValidator(acceptIssuers = acceptIssuers)
            .toOAuth2TokenValidator()
        val audienceValidator: OAuth2TokenValidator<Jwt> =
            jwtAudienceClaimValidator(acceptAudiences = acceptAudiences)
                .toOAuth2TokenValidator()

        return jwtCompoundOAuth2TokenValidator(
            defaultValidator, issuerValidator, audienceValidator
        )
    }


}
