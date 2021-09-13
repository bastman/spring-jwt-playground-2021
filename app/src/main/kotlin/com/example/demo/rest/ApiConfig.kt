package com.example.demo.rest

import com.example.demo.config.security.basicauth.BasicAuthConfig
import com.example.demo.config.security.jwt.resourceserver.JwtAuthConfig
import com.example.demo.config.security.jwt.resourceserver.toAuthStrategyName
import org.springframework.stereotype.Component

@Component
class ApiConfig(
    private val jwtAuthConfig: JwtAuthConfig,
    private val basicAuthConfig: BasicAuthConfig,
) {
    val title: String
        get() = "Demo App - API (jwt-auth: ${jwtAuthConfig.toAuthStrategyName()} basic-auth.enabled: ${basicAuthConfig.enabled})"
}


