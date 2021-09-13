package com.example.demo.config.security

import com.example.demo.config.security.basicauth.BasicAuthConfig
import com.example.demo.config.security.jwt.resourceserver.JwtAuthConfig
import com.example.demo.config.security.jwt.resourceserver.JwtResourceServerDefault
import com.example.demo.config.security.jwt.resourceserver.JwtResourceServerFakeRS256
import com.example.demo.config.security.jwt.resourceserver.JwtResourceServerHS256
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
    private val jwtAuthConfig: JwtAuthConfig,
    private val basicAuthConfig: BasicAuthConfig,
) {
    companion object : KLogging()

    private val endpointsFullyAuthenticated: List<String> = listOf("/api/**")
    private val endpointsUnsecured: List<String> = listOf(
        // index
        "/",
        // actuator
        "/health",
        "/info",
        "/prometheus",

        // springfox-swagger2 (2.9.x)
        "/v2/api-docs",
        "/configuration/ui",
        "/swagger-resources/**",
        "/configuration/security",
        "/swagger-ui.html",
        "/webjars/**",

        // basic-auth
        "/csrf", // ???

        // custom: fake-authorization-server
        "/.well-known/**",
        "/oauth/**",
    )

    @Bean
    fun springWebFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .authorizeRequests {
                it
                    .antMatchers(*(endpointsUnsecured.toTypedArray())).permitAll()
                    .antMatchers(*(endpointsFullyAuthenticated.toTypedArray())).fullyAuthenticated()
                    .anyRequest().authenticated()
            }
            .let {
                when (jwtAuthConfig) {
                    is JwtAuthConfig.JwtNone -> it.oauth2ResourceServer { configurer -> configurer.disable() }
                    else -> it.oauth2ResourceServer { configureJwtResourceServer(it, jwtAuthConfig) }
                }
            }
            .let {
                when (basicAuthConfig.enabled) {
                    true -> it.httpBasic { }
                    else -> it.httpBasic { configurer -> configurer.disable() }
                }
            }
            .build()
    }

    private fun configureJwtResourceServer(
        rs: OAuth2ResourceServerConfigurer<HttpSecurity?>, authConfig: JwtAuthConfig,
    ): Unit = when (authConfig) {
        is JwtAuthConfig.JwtNone -> {
            rs.disable()
            Unit
        }
        is JwtAuthConfig.JwtDefault -> JwtResourceServerDefault
            .configure(rs = rs, issuer = authConfig.issuer, audience = authConfig.audience)
        is JwtAuthConfig.JwtFakeRS256 -> JwtResourceServerFakeRS256
            .configure(
                rs = rs,
                issuer = authConfig.issuer,
                audience = authConfig.audience,
                rsaKey = authConfig.rsaKey
            )
        is JwtAuthConfig.JwtFakeHS256 -> JwtResourceServerHS256
            .configure(
                rs = rs,
                issuer = authConfig.issuer,
                audience = authConfig.audience,
                hs256Secret = authConfig.hs256Secret
            )
    }


    @Autowired
    fun configureBasicAuth(auth: AuthenticationManagerBuilder) {
        val authConfig: BasicAuthConfig = basicAuthConfig
        val users = when (authConfig.enabled) {
            false -> null
            true -> authConfig.users
        } ?: return

        var builder = auth
            .inMemoryAuthentication()
            .passwordEncoder(InsecurePlainTextBasicAuthPasswordDecoder())

        if (users.isEmpty()) {
            logger.warn { "AppAuth - No valid user defined" }
        } else {
            users
                .forEach {
                    val username = it.key
                    val password = it.value.password
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
