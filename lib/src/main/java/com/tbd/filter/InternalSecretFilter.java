package com.tbd.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class InternalSecretFilter extends OncePerRequestFilter {

    private final String expectedSecret;

    public InternalSecretFilter(String expectedSecret) {
        this.expectedSecret = expectedSecret;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        String path = request.getRequestURI();

        // 1. Always allow Actuator (K8s needs this to check if pod is alive)
        if (path.contains("/actuator")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Check for the secret header on ALL other requests
        String receivedSecret = request.getHeader("X-Internal-Secret");

        if (receivedSecret == null || !receivedSecret.equals(expectedSecret)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Direct Access Forbidden. Please go through API Gateway.\"}");
            return;
        }

        // 3. If secret is valid, continue to Spring Security (JWT check, etc.)
        filterChain.doFilter(request, response);
    }
}
