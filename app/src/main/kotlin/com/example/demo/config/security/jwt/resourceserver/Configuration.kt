package com.example.demo.config.security.jwt.resourceserver

import com.example.demo.util.jwt.RSAKeyFactory
import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.annotation.JsonTypeName
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.module.kotlin.convertValue
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.jwk.RSAKey
import org.springframework.boot.context.properties.bind.Bindable
import org.springframework.boot.context.properties.bind.Binder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.env.Environment


@JsonTypeInfo(
    use = JsonTypeInfo.Id.NAME,
    include = JsonTypeInfo.As.EXISTING_PROPERTY,
    property = "strategy",
    visible = true
)
sealed class JwtAuthConfig(

) {

    @JsonTypeName("JwtNone")
    object JwtNone : JwtAuthConfig()

    @JsonTypeName("JwtDefault")
    data class JwtDefault(
        val issuer: String,
        val audience: String,
    ) : JwtAuthConfig()

    @JsonTypeName("JwtFakeHS256")
    data class JwtFakeHS256(
        val issuer: String,
        val audience: String,
        val hs256Secret: String,
    ) : JwtAuthConfig()

    @JsonTypeName("JwtFakeRS256")
    data class JwtFakeRS256(
        val issuer: String,
        val audience: String,
        val rsaKeyB64: String,
    ) : JwtAuthConfig() {

        val rsaKey: RSAKey by lazy {
            RSAKeyFactory.rsaKeyOfB64String(rsaKeyB64 = rsaKeyB64)
        }
    }

}

fun JwtAuthConfig.toAuthStrategyName(): String = "${this::class.simpleName}"

@Configuration(proxyBeanMethods = false)
class JwtAuthConfiguration {

    @Bean
    fun jwtAuthConfig(env: Environment): JwtAuthConfig {
        val q = "app.auth.bearer"
        val asMap: Map<String, Any?> = Binder
            .get(env)
            .bind(q, Bindable.mapOf(String::class.java, Any::class.java))
            .get()
        val converted: JwtAuthConfig = JSON.convertValue(asMap)
        return converted
    }

    private val JSON = jacksonObjectMapper()
        .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
}
