package com.example.demo.config.security.jwt.resourceserver

import com.example.demo.util.jwt.jwtAudienceClaimValidator
import com.example.demo.util.jwt.jwtCompoundOAuth2TokenValidator
import com.example.demo.util.jwt.jwtIssuerClaimValidator
import com.example.demo.util.jwt.toOAuth2TokenValidator
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtValidators

object JwtResourceServerCommon {

    fun jwtValidator(
        acceptIssuers: List<String>, acceptAudiences: List<String>,
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
