package com.example.demo.config.swagger

import com.example.demo.config.security.basicauth.BasicAuthConfig
import com.example.demo.config.security.jwt.resourceserver.JwtAuthConfig
import com.example.demo.rest.ApiConfig
import mu.KLogging
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import springfox.documentation.builders.RequestHandlerSelectors
import springfox.documentation.service.*
import springfox.documentation.spi.DocumentationType
import springfox.documentation.spi.service.contexts.SecurityContext
import springfox.documentation.spring.web.plugins.Docket
import springfox.documentation.swagger2.annotations.EnableSwagger2

@Configuration
@EnableSwagger2
class SwaggerConfig(
    private val apiConfig: ApiConfig,
    private val jwtAuthConfig: JwtAuthConfig,
    private val basicAuthConfig: BasicAuthConfig,
) {
    companion object : KLogging()

    private val authScopes: List<AuthorizationScope> = emptyList()

    // see: https://github.com/springfox/springfox/issues/2908
    // see: https://github.com/springfox/springfox/issues/3518
    private val basicAuthScheme = BasicAuth("basicAuth")
    private val bearerAuthScheme = ApiKey("Bearer <token>", "Authorization", "header")

    private val basicAuthReference: SecurityReference =
        SecurityReference(basicAuthScheme.name, *(authScopes.toTypedArray()))
    private val bearerAuthReference: SecurityReference =
        SecurityReference(bearerAuthScheme.name, *(authScopes.toTypedArray()))

    private fun securitySchemes(): List<SecurityScheme> = listOfNotNull(
        when (jwtAuthConfig) {
            is JwtAuthConfig.JwtDefault, is JwtAuthConfig.JwtFakeRS256, is JwtAuthConfig.JwtFakeHS256 -> bearerAuthScheme
            is JwtAuthConfig.JwtNone -> null
        },
        when (basicAuthConfig.enabled) {
            true -> basicAuthScheme
            false -> null
        }
    )

    private fun securityReferences(): List<SecurityReference> = listOfNotNull(
        when (jwtAuthConfig) {
            is JwtAuthConfig.JwtDefault, is JwtAuthConfig.JwtFakeRS256, is JwtAuthConfig.JwtFakeHS256 -> bearerAuthReference
            is JwtAuthConfig.JwtNone -> null
        },
        when (basicAuthConfig.enabled) {
            true -> basicAuthReference
            false -> null
        }
    )

    @Bean
    fun mainApi(): Docket = apiConfig.toDocket()
        .securitySchemes(securitySchemes())
        .securityContexts(
            listOf(
                securityContextFromReferences(
                    securityReferences = securityReferences()
                )
            )
        )
        .useDefaultResponseMessages(false)
        .select()
        .apis(RequestHandlerSelectors.basePackage(apiConfig.getBasePackageName()))
        .build()
}


private fun ApiConfig.getBasePackageName(): String = this::class.java.`package`.name
private fun ApiConfig.toApiInfo(): ApiInfo = springfox.documentation.builders.ApiInfoBuilder()
    .title(this.title)
    .build()

private fun ApiConfig.toDocket(): Docket = Docket(DocumentationType.SWAGGER_2)
    .apiInfo(this.toApiInfo())

private fun securityContextFromReferences(
    securityReferences: List<SecurityReference>,
): SecurityContext = SecurityContext
    .builder()
    .securityReferences(securityReferences)
    .forPaths { input -> true } // springfox 2.x
    // .operationSelector { ctx -> true } // springfox 3.x
    .build()
