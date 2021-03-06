package com.example.demo.config.security.jwt.resourceserver

import com.example.demo.util.jwt.JwtRS256
import com.nimbusds.jose.jwk.RSAKey
import mu.KLogging
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder

object JwtResourceServerFakeRS256 : KLogging() {

    fun configure(
        rs: OAuth2ResourceServerConfigurer<HttpSecurity?>,
        issuer: String,
        audience: String,
        rsaKey: RSAKey,
    ) {
        rs.jwt {
            val validator: DelegatingOAuth2TokenValidator<Jwt> = JwtResourceServerCommon.jwtValidator(
                acceptIssuers = listOf(issuer),
                acceptAudiences = listOf(audience)
            )
            val decoder: NimbusJwtDecoder = jwtDecoder(rsaKey)
            decoder.setJwtValidator(validator)
            it.decoder(decoder)
        }
        logger.info { "==== jwt resource server ===" }
        logger.info { "=> accept issuer: $issuer audience: $audience" }
    }

    private fun jwtDecoder(rsaKey: RSAKey): NimbusJwtDecoder = JwtRS256
        .of(rsaKey)
        .jwtDecoder {}

    /*
    private fun jwtDecoder(rsaPublicKey: RSAPublicKey): NimbusJwtDecoder {
        return NimbusJwtDecoder.withPublicKey(rsaPublicKey).build()
    }

    private fun jwtDecoder(jwkSetUri: String): NimbusJwtDecoder {
        // e.g.: "http://localhost:8080/.well-known/jwks.json"
        return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build()
    }
     */
}
