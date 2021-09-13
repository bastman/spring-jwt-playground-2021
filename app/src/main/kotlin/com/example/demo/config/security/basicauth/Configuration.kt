package com.example.demo.config.security.basicauth

import com.example.demo.config.security.jwt.resourceserver.JwtAuthConfig
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.module.kotlin.convertValue
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.springframework.boot.context.properties.bind.Bindable
import org.springframework.boot.context.properties.bind.Binder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.env.Environment

data class BasicAuthConfig(
    val enabled:Boolean,
    val users:Map<String, User>?
) {
    data class User(val password:String)
}

@Configuration(proxyBeanMethods = false)
class BasicAuthConfiguration {

    @Bean
    fun basicAuthConfig(env: Environment): BasicAuthConfig {
        val q = "app.auth.basicauth"
        val asMap: Map<String, Any?> = Binder
            .get(env)
            .bind(q, Bindable.mapOf(String::class.java, Any::class.java))
            .get()
        val converted: BasicAuthConfig = JSON.convertValue(asMap)
        return converted
    }

    private val JSON = jacksonObjectMapper()
        .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
}
