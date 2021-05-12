package com.example.demo.config.security

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtDecoders
import org.springframework.security.oauth2.jwt.JwtValidators
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.web.SecurityFilterChain

/**
 * see: https://github.com/hantsy/spring-security-auth0-sample/blob/master/api/src/main/java/com/example/demo/config/SecurityConfig.java
 */

@Configuration
class SecurityConfig {
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
            //.oauth2ResourceServer { it.jwt() }
            .build()
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
