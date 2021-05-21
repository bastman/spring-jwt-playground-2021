# spring-jwt-playground-2021
let's check how to bearer-auth in 2021 :)

## scope
- single-tenant resource-server
    - validate jwt claims: exp, iss, aud 
- simple fake authorization server:
    - why? ... to simplify local development
    - generate self-signed jwt
    - sign any arbitrary jwt payload using (RS256, HS256)
- spring boot (mvc)


## how to run? 

### profiles

- auth-prod: requires issuer-uri + audience as env variables
- auth-fake: accepts/generates self-signed jwt (HS256, RS256). Do not use in production!

```
VM Options:

-D.spring.profiles.active=auth-prod
-D.spring.profiles.active=auth-fakeRS256
-D.spring.profiles.active=auth-fakeHS256
```

### swagger:

- http://localhost:8080/v2/api-docs
- http://localhost:8080/swagger-ui.html

```
click "authorize". 
enter "Bearer <your jwt>". 
click "login"
```

### use case: generate self-signed jwt

```
# requires profile: auth-fakeRS256  (or auth-fakeHS256)

$ curl -v -X POST "http://localhost:8080/oauth/example-token"
--> returns a self-signed jwt

$ curl -X GET "http://localhost:8080/api/me" -H "Authorization: Bearer <your token>"


```

### use case: sign any arbitrary jwt payload

```
# requires profile: auth-fakeRS256  (or auth-fakeHS256)

# payload to sign ...

{
  "https://example.com/claims/userid": "my-issuer-1|my-user-id-1",
  "https://app.example.com/roles": [
    "my-role-1",
    "my-role-2"
  ],
  "https://example.com/claims/given_name": "my-given-name",
  "https://example.com/claims/family_name": "my-family-name",
  "https://example.com/claims/email": "my.email@example.com",
  "iss": "https://my-issuer-1.local",
  "sub": "my-issuer-1|my-user-id-1",
  "aud": [
    "my-audience-1",
    "my-audience-2"
  ],
  "iat": 1604327123,
  "exp": 1604377523,
  "scope": "openid profile email"
}


$ curl -v -X POST "http://localhost:8080/oauth/sign-token" -H "Content-Type: application/json" -d "{ \"https://example.com/claims/userid\": \"my-issuer-1|my-user-id-1\", \"https://app.example.com/roles\": [ \"my-role-1\", \"my-role-2\" ], \"https://example.com/claims/given_name\": \"my-given-name\", \"https://example.com/claims/family_name\": \"my-family-name\", \"https://example.com/claims/email\": \"my.email@example.com\", \"iss\": \"https://my-issuer-1.local\", \"sub\": \"my-issuer-1|my-user-id-1\", \"aud\": [ \"my-audience-1\", \"my-audience-2\" ], \"iat\": 1604327123, \"exp\": 1604377523, \"scope\": \"openid profile email\"}"

--> returns a self-signed jwt

$ curl -X GET "http://localhost:8080/api/me" -H "Authorization: Bearer <your token>"

```

## see
- https://itnext.io/secures-rest-apis-with-spring-security-5-and-auth0-41d579ca1e27
- https://github.com/spring-projects/spring-security/blob/main/docs/manual/src/docs/asciidoc/_includes/servlet/oauth2/oauth2-resourceserver.adoc
- https://github.com/hantsy/spring-security-auth0-sample/tree/master/api
- https://github.com/hantsy/spring-security-auth0-sample/blob/master/docs/api.md
- https://docs.spring.io/spring-security/site/docs/current/reference/html5/#oauth2resourceserver
- https://connect2id.com/products/nimbus-jose-jwt/examples/validating-jwt-access-tokens
- https://connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-hmac
- https://bitbucket.org/connect2id/nimbus-jose-jwt/src/master/
- https://github.com/spring-projects-experimental/spring-authorization-server  
### multiple jwks algorithms
- https://github.com/sdoxsee/examples/tree/master/multi-tenant-jwt-resourceserver
- https://docs.spring.io/spring-security/site/docs/current/reference/html5/#oauth2resourceserver-multitenancy
- https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/353/support-jwks-with-multiple-algorithms
- https://bitbucket.org/connect2id/nimbus-jose-jwt/pull-requests/65
  
- https://bitbucket.org/connect2id/nimbus-jose-jwt/src/2b59e93a6a3bd1fed673518ac894d1c18c17d59b/src/test/java/com/nimbusds/jose/proc/JWSVerificationKeySelectorTest.java
- https://www.novatec-gmbh.de/en/blog/how-to-support-different-jwts-in-your-spring-boot-application/
- https://github.com/spring-projects-experimental/spring-authorization-server/blob/main/oauth2-authorization-server/src/test/java/org/springframework/security/config/annotation/web/configurers/oauth2/server/authorization/JwkSetTests.java    
- https://github.com/spring-projects-experimental/spring-authorization-server/blob/5e0fe9c8622b6f31de86e981cb10f0e425c425a3/oauth2-authorization-server/src/test/java/org/springframework/security/oauth2/server/authorization/web/NimbusJwkSetEndpointFilterTests.java




## alternatives - the minimalistic example ...
 ```
 
@Bean
    fun springWebFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            .httpBasic { it.disable() }
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .authorizeRequests {
                it
                    .antMatchers(*(endpointsUnsecured.toTypedArray())).permitAll()
                    .antMatchers(*(endpointsFullyAuthenticated.toTypedArray())).fullyAuthenticated()
                    .anyRequest().authenticated()
            }
            .oauth2ResourceServer { superSimpleResourceServer(it) }
            .build()
    }

    private fun superSimpleResourceServer(rs: OAuth2ResourceServerConfigurer<HttpSecurity?>) {
        val issuer = "https://my-issuer.example.com/"
        val validator:OAuth2TokenValidator<Jwt> = JwtValidators.createDefaultWithIssuer(issuer)
        // note: does not validate audience
        val decoder:NimbusJwtDecoder = JwtDecoders.fromIssuerLocation(issuer) as NimbusJwtDecoder
        decoder.setJwtValidator(validator)
        rs.jwt {
            it.decoder(decoder)
        }
    } 
 
 ```
