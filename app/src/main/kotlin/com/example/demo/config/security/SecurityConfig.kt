package com.example.demo.config.security

import com.example.demo.config.security.jwt.resourceserver.JwtResourceServerFakeRS256
import com.example.demo.config.security.jwt.resourceserver.JwtResourceServerHS256
import com.example.demo.config.security.jwt.resourceserver.JwtResourceServerProd
import com.example.demo.config.security.jwt.resourceserver.MyAuthConfig
import mu.KLogging
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain

/**
 * see: https://github.com/hantsy/spring-security-auth0-sample/blob/master/api/src/main/java/com/example/demo/config/SecurityConfig.java
 */

@Configuration(proxyBeanMethods = false)
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

        // custom: fake-authorization-server
        "/.well-known/**",
        "/oauth/**",
    )

    @Bean
    fun springWebFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            //.httpBasic { it.disable() }
            .httpBasic { } // enable basic auth
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
            is MyAuthConfig.JwtFakeRS256 -> JwtResourceServerFakeRS256
                .configure(
                    rs = rs,
                    issuer = authConfig.issuer,
                    audience = authConfig.audience,
                    rsaKey = authConfig.rsaKey
                )
            is MyAuthConfig.JwtFakeHS256 -> JwtResourceServerHS256
                .configure(
                    rs = rs,
                    issuer = authConfig.issuer,
                    audience = authConfig.audience,
                    hs256Secret = authConfig.hs256Secret
                )
        }

    @Autowired
    fun configureBasicAuth(auth: AuthenticationManagerBuilder) {
        var builder = auth
            .inMemoryAuthentication()
            .passwordEncoder(InsecurePlainTextBasicAuthPasswordDecoder())

        val validUsers = listOf(
            "foo-user" to "foo-password"
        )
        if (validUsers.isEmpty()) {
            logger.warn { "AppAuth - No valid user defined" }
        } else {
            validUsers
                .forEach {
                    val username = it.first
                    val password = it.second
                    val roles: List<String> = listOf()
                    logger.info { "AppAuth - add User: username=$username roles=$roles" }
                    builder = builder
                        .withUser(username)
                        .password(password)
                        .roles(*roles.toTypedArray())
                        .and()
                }
        }


    }

}


class InsecurePlainTextBasicAuthPasswordDecoder : PasswordEncoder {
    // well we should use BCrypt or sth. instead
    override fun encode(rawPassword: CharSequence?): String = NoOpPasswordEncoder
        .getInstance().encode(rawPassword)

    override fun matches(rawPassword: CharSequence?, encodedPassword: String?): Boolean = NoOpPasswordEncoder
        .getInstance().matches(rawPassword, encodedPassword)
}
