package com.example.demo.config.security

import com.example.demo.config.security.jwt.resourceserver.JwtResourceServerHS256
import com.example.demo.config.security.jwt.resourceserver.JwtResourceServerProd
import com.example.demo.config.security.jwt.resourceserver.MyAuthConfig
import mu.KLogging
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.config.http.SessionCreationPolicy
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
        "/token/**",
        "/.well-known/**"
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

    private fun resourceServer(rs: OAuth2ResourceServerConfigurer<HttpSecurity?>, authConfig: MyAuthConfig): Unit =
        when (authConfig) {
            is MyAuthConfig.JwtProd -> JwtResourceServerProd
                .configure(rs = rs, issuer = authConfig.issuer, audience = authConfig.audience)
            is MyAuthConfig.JwtFake -> JwtResourceServerHS256
                .configure(
                    rs = rs,
                    issuer = authConfig.issuer,
                    audience = authConfig.audience,
                    hs256Secret = authConfig.hs256Secret
                )
        }

}
