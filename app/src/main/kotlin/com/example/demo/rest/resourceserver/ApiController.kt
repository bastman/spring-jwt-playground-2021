package com.example.demo.rest.resourceserver

import mu.KLogging
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.User
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.web.authentication.WebAuthenticationDetails
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import springfox.documentation.annotations.ApiIgnore

@RestController
class ResourceServerApiController(
) {
    companion object : KLogging()

    @GetMapping("/api/me")
    fun me(
        @ApiIgnore authentication: Authentication,
        //@ApiIgnore authentication: JwtAuthenticationToken
        // ,@ApiIgnore @AuthenticationPrincipal  oidcUser: OidcUser
    ): Any {

        return when (authentication) {
            is JwtAuthenticationToken -> {
                val jwt: Jwt = authentication.token
                mapOf(
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
            is UsernamePasswordAuthenticationToken -> {
                mapOf(
                    "foo" to "bar",
                    "auth" to mapOf(
                        "name" to authentication.name,
                        "authorities" to authentication.authorities,
                        "principal" to authentication.principal as User, // org.springframework.security.core.userdetails.User
                        "credentials" to authentication.credentials, // null
                        "details" to authentication.details as WebAuthenticationDetails
                    )
                )
            }
            else -> mapOf(
                "foo" to "bar",
            )

        }


    }

}
