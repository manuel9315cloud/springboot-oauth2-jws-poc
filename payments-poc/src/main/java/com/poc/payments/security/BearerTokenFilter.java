
package com.poc.payments.security;

import com.poc.payments.service.TokenValidationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class BearerTokenFilter extends OncePerRequestFilter {

    private final TokenValidationService tokenValidationService;

    public BearerTokenFilter(
            TokenValidationService tokenValidationService) {
        this.tokenValidationService = tokenValidationService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String authorization =
                request.getHeader("Authorization");

        // 1. Verificar que exista el Bearer Token
        if (authorization == null ||
                !authorization.startsWith("Bearer ")) {

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // 2. Extraer el Access Token
        String token = authorization.substring(7);

        try {

            // 3. Consultar a WAM si el token es válido
            boolean valid = tokenValidationService.validate(token);

            if (!valid) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            // 4. Crear autenticación para Spring Security
            var authentication =
                    new UsernamePasswordAuthenticationToken(
                            "nubiz-client",
                            null,
                            List.of()
                    );

            // 5. Registrar autenticación en el contexto
            SecurityContextHolder.getContext()
                    .setAuthentication(authentication);

            // 6. Continuar hacia el controlador
            filterChain.doFilter(request, response);

        } catch (Exception exception) {

            SecurityContextHolder.clearContext();

            response.setStatus(
                    HttpServletResponse.SC_SERVICE_UNAVAILABLE
            );
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {

        String path = request.getServletPath();

        return path.startsWith("/test/jws/")
                || path.equals("/payments/health");
    }
}
