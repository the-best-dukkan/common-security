package com.tbd;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@RequiredArgsConstructor
public class JjwtJwtDecoder implements JwtDecoder {

    private final String jwtSecret;
    private final String jwtIssuer;

    @Override
    public Jwt decode(String token) throws JwtException {

        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));

        // Use JJWT to parse the token
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .requireIssuer(jwtIssuer)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        // Convert JJWT Claims to Spring Security JWT object
        return new Jwt(
                token,
                claims.getIssuedAt().toInstant(),
                claims.getExpiration().toInstant(),
                Map.of("alg", "HS256", "typ", "JWT"), // Header
                claims // Payload
        );
    }
}
