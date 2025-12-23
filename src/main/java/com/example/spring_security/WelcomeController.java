package com.example.spring_security;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WelcomeController {

    @GetMapping("/")
    public String welcome() {
        return "Bem-vindo ao Spring Security!";
    }

    @GetMapping("/users")
    public String users() {
        return "Bem-vindo, usuário!";
    }

    @GetMapping("/managers")
    public String managers() {
        return "Bem-vindo, gerente!";
    }
}

