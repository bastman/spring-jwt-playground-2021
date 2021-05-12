package com.example.demo.rest

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class ApiController {

    @GetMapping("/api/me")
    fun me(): Any {
        return mapOf(
            "foo" to "bar"
        )
    }
}
