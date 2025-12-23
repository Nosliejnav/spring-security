package com.example.spring_security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
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

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Desabilita CSRF para facilitar testes locais
                .csrf(csrf -> csrf.disable())

                // Define as regras de autorização baseadas na imagem
                .authorizeHttpRequests(auth -> auth
                        // 1. Permite acesso total à raiz (home) e ao login sem senha
                        .requestMatchers("/").permitAll()
                        .requestMatchers(HttpMethod.POST,"/login").permitAll()


                        // 2. Acesso apenas para quem tem o papel MANAGERS
                        .requestMatchers("/managers").hasRole("MANAGERS")

                        // 3. Acesso para quem tem papel USERS ou MANAGERS
                        .requestMatchers("/users").hasAnyRole("USERS", "MANAGERS")

                        // 4. Qualquer outra rota não listada acima exige login
                        .anyRequest().authenticated()
                )

                // Habilita o formulário de login e permite que todos o vejam
                .formLogin(form -> form.permitAll());

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        // Criando usuário comum
        UserDetails user = User.withUsername("user")
                .password("user123")
                .roles("USERS")
                .build();

        // Criando usuário administrador
        UserDetails admin = User.withUsername("admin")
                .password("master123")
                .roles("MANAGERS")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // NoOpPasswordEncoder: não criptografa a senha (apenas para estudo)
        return NoOpPasswordEncoder.getInstance();
    }
}