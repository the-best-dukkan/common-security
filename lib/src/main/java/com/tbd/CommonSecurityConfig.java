package com.tbd;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@AutoConfiguration
@EnableWebSecurity
@RequiredArgsConstructor
public class CommonSecurityConfig {

    @Value("${spring.application.name}")
    private String appName;

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.issuer}")
    private String jwtIssuer;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/internal/users/**", "/" + appName + "/actuator/**").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth -> oauth
                        .jwt(Customizer.withDefaults())
                );
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return new JjwtJwtDecoder(jwtSecret, jwtIssuer);
    }
}
