package com.example.demo.config.security.jwt.resourceserver

import com.example.demo.util.jwt.JwtHS256
import mu.KLogging
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder

object JwtResourceServerHS256 : KLogging() {

    fun configure(
        rs: OAuth2ResourceServerConfigurer<HttpSecurity?>,
        issuer: String,
        audience: String,
        hs256Secret: String
    ) {
        rs.jwt {
            val validator: DelegatingOAuth2TokenValidator<Jwt> = JwtResourceServerCommon.jwtValidator(
                acceptIssuers = listOf(issuer),
                acceptAudiences = listOf(audience)
            )
            val decoder: NimbusJwtDecoder = jwtDecoder(hs256Secret = hs256Secret)
            decoder.setJwtValidator(validator)
            it.decoder(decoder)
        }

        logger.info { "==== jwt resource server ===" }
        logger.info { "=> accept issuer: $issuer audience: $audience" }
    }

    private fun jwtDecoder(hs256Secret: String): NimbusJwtDecoder = JwtHS256(secret = hs256Secret)
        .jwtDecoder {}

}
