package com.example.demo.config.swagger

import com.example.demo.rest.ApiConfig
import mu.KLogging
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import springfox.documentation.builders.RequestHandlerSelectors
import springfox.documentation.service.ApiInfo
import springfox.documentation.spi.DocumentationType
import springfox.documentation.spring.web.plugins.Docket
import springfox.documentation.swagger2.annotations.EnableSwagger2

@Configuration
@EnableSwagger2
class SwaggerConfig(
    private val apiConfig: ApiConfig
) {
    companion object : KLogging()

    @Bean
    fun mainApi(): Docket = apiConfig.toDocket()
        //.securitySchemes(apiKeyDefs.toSecuritySchemes())
        //.securityContexts(listOf(securityContext(apiKeyDefs.toSecurityReferences())))
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
