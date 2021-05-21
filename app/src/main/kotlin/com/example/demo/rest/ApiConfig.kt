package com.example.demo.rest

import com.example.demo.config.security.jwt.resourceserver.MyAuthConfig
import com.example.demo.config.security.jwt.resourceserver.toAuthStrategyName
import org.springframework.stereotype.Component

@Component
class ApiConfig(
    private val myAuthConfig: MyAuthConfig
) {
    val title: String
        get() = "Demo App - API (auth: ${myAuthConfig.toAuthStrategyName()})"
}


