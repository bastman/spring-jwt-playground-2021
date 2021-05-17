package com.example.demo.config.security.jwt

import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.annotation.JsonTypeName
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.module.kotlin.convertValue
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
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

    @JsonTypeName("JwtFake")
    data class JwtFake(
        val issuer: String,
        val audience: String,
        val hs256Secret: String,
    ) : MyAuthConfig()

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
