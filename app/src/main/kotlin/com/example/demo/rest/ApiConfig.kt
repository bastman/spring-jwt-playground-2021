package com.example.demo.rest

import org.springframework.stereotype.Component

@Component
class ApiConfig(
    // @Value(value = "\${app.envName}") val env: AppEnvName,
    // @Value(value = "\${app.serviceName}") val service: String
) {
    val title: String
        //get() = "API $service ($env)"
        get() = "Demo App - API"
}
