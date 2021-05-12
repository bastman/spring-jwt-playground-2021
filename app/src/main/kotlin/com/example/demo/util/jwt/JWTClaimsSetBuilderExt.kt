package com.example.demo.util.jwt

import com.nimbusds.jwt.JWTClaimsSet
import java.time.Instant
import java.util.*

fun jwtClaimSet(block: JWTClaimsSetBuilderSpec? = null): JWTClaimsSet {
    return JWTClaimsSet.Builder()
        .let {
            if (block != null) {
                it.apply(block)
            }
            it
        }
        .build()
}

fun JWTClaimsSet.Builder.issueTime(iat: Instant): JWTClaimsSet.Builder = this.issueTime(Date.from(iat))
fun JWTClaimsSet.Builder.expirationTime(exp: Instant): JWTClaimsSet.Builder = this.expirationTime(Date.from(exp))

private typealias JWTClaimsSetBuilderSpec = JWTClaimsSet.Builder.() -> Unit
