package com.example.spring_security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Classe principal de configuração de segurança da aplicação
 */
@Configuration // Indica que esta classe contém configurações do Spring
@EnableWebSecurity // Ativa o Spring Security na aplicação
@EnableMethodSecurity(prePostEnabled = true)
// Permite usar anotações como @PreAuthorize e @PostAuthorize nos métodos
public class WebSecurityConfig {

    /**
     * Define a cadeia de filtros de segurança (Security Filter Chain)
     * Aqui configuramos como as requisições HTTP serão protegidas
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Desabilita proteção CSRF (somente para estudo / APIs simples)
                // Em aplicações web reais, o ideal é manter o CSRF ativado
                .csrf(csrf -> csrf.disable())

                // Define as regras de autorização
                .authorizeHttpRequests(auth -> auth
                        // Todas as requisições precisam estar autenticadas
                        .anyRequest().authenticated()
                )

                // Habilita autenticação simples com formulário de login
                // O Spring fornece uma página de login padrão
                .formLogin();

        // Finaliza e constrói a configuração de segurança
        return http.build();
    }

    /**
     * Define os usuários da aplicação
     * Aqui usamos usuários em memória (apenas para estudo)
     */
    @Bean
    public UserDetailsService userDetailsService() {

        // Usuário comum
        UserDetails user = User.withUsername("user")
                // Senha em texto puro (não usar em produção)
                .password("user123")
                .roles("USERS")
                .build();

        // Usuário administrador
        UserDetails admin = User.withUsername("admin")
                // Senha em texto puro (não usar em produção)
                .password("master123")
                .roles("MANAGERS")
                .build();

        // Gerenciador de usuários em memória
        return new InMemoryUserDetailsManager(user, admin);
    }

    /**
     * Define o encoder de senha
     * NoOpPasswordEncoder não aplica criptografia
     * Usado apenas para estudo e testes
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}