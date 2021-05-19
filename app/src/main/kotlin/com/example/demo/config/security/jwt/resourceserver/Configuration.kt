package com.example.demo.config.security.jwt.resourceserver

import com.example.demo.util.jwt.RSA
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
sealed class MyAuthConfig(

) {

    @JsonTypeName("JwtProd")
    data class JwtProd(
        val issuer: String,
        val audience: String
    ) : MyAuthConfig()

    @JsonTypeName("JwtFakeHS256")
    data class JwtFakeHS256(
        val issuer: String,
        val audience: String,
        val hs256Secret: String,
    ) : MyAuthConfig()

    @JsonTypeName("JwtFakeRSA256")
    data class JwtFakeRSA256(
        val issuer: String,
        val audience: String,
        val rsaKeyB64: String
    ) : MyAuthConfig() {

        val rsaKey: RSAKey by lazy {
            RSA.rsaKeyFromJsonStringB64(rsaKeyB64 = rsaKeyB64)
        }
    }

}

@Configuration
class MyAuthConfiguration {

    @Bean
    fun myAuthConfig(env: Environment): MyAuthConfig {
        val q = "app.auth"
        val asMap: Map<String, Any?> = Binder
            .get(env)
            .bind(q, Bindable.mapOf(String::class.java, Any::class.java))
            .get()
        val converted: MyAuthConfig = JSON.convertValue(asMap)
        return converted
    }

    private val JSON = jacksonObjectMapper()
        .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
}
