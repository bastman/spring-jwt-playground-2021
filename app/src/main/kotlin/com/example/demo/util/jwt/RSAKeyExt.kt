package com.example.demo.util.jwt

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import net.minidev.json.JSONObject
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*

object RSAKeyFactory {

    fun rsaKeyOfB64String(rsaKeyB64: String): RSAKey {
        val rsaKeyJson: String = Base64.getDecoder().decode(rsaKeyB64).decodeToString()
        val rsaKey: RSAKey = RSAKey.parse(rsaKeyJson)
        return rsaKey
    }

    fun generateRSAKey(): RSAKey {
        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        val keyPair: KeyPair = keyPairGenerator.genKeyPair()
        val publicKey: RSAPublicKey = keyPair.public as RSAPublicKey
        val privateKey: RSAPrivateKey = keyPair.private as RSAPrivateKey
        return RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
    }
}

fun RSAKey.toPublicJWKSetJSONString(): String {
    // exposes public keys only
    // to be used for exposing authorization-server endpoint: GET .well-known/jwks.json
    val jwkSet = JWKSet(this)
    return jwkSet.toPublicJWKSet().toJSONObject(true).toJSONString()
}

fun RSAKey.toRSAKeyB64String(): String {
    // exposes private + public key
    // to be used for serialize/deserialize an rsa-key
    // Note: must not be exposed to the world!
    val jsonObject: JSONObject = this.toJSONObject()
    val rsaKeyJson: String = jsonObject.toJSONString()
    return Base64.getEncoder().encodeToString(rsaKeyJson.toByteArray())
}

