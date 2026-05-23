package com.rashed.ecommerce.apigateway.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

@Slf4j
@Component

public class UserContextFilter implements GlobalFilter, Ordered {

    private static final String USER_ID_HEADER = "X-User-Id";
    private static final String USER_EMAIL_HEADER = "X-User-Email";
    private static final String USER_ROLE_HEADER = "X-User-Role";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        String authorizationHeader = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        log.info(
                "UserContextFilter called. path={}, hasAuthorizationHeader={}",
                path,
                authorizationHeader != null
        );

        Mono<ServerWebExchange> mutatedExchangeMono = ReactiveSecurityContextHolder.getContext()
                .map(securityContext -> securityContext.getAuthentication())
                .doOnNext(authentication ->
                        log.info("Authentication type={}", authentication.getClass().getName())
                )
                .filter(authentication -> authentication instanceof JwtAuthenticationToken)
                .cast(JwtAuthenticationToken.class)
                .map(authentication -> addUserContextHeaders(exchange, authentication))
                .switchIfEmpty(Mono.fromSupplier(() -> {
                    log.info("No authenticated JWT found for path={}", path);
                    return exchange;
                }));

        return mutatedExchangeMono.flatMap(chain::filter);
    }

    private ServerWebExchange addUserContextHeaders(
            ServerWebExchange exchange,
            JwtAuthenticationToken authentication
    ) {
        Jwt jwt = authentication.getToken();

        String userId = extractUserId(jwt);
        String email = jwt.getClaimAsString("email");
        String role = extractRole(jwt);

        log.info(
                "Extracted user context. userId={}, email={}, role={}",
                userId,
                email,
                role
        );

        ServerHttpRequest mutatedRequest = exchange.getRequest()
                .mutate()
                .headers(headers -> {
                    /*
                     * Remove any incoming user-context headers first.
                     * This prevents clients from spoofing them manually.
                     */
                    headers.remove(USER_ID_HEADER);
                    headers.remove(USER_EMAIL_HEADER);
                    headers.remove(USER_ROLE_HEADER);

                    if (userId != null) {
                        headers.add(USER_ID_HEADER, userId);
                        log.info(
                                "headers userId. userId={}",
                                userId
                        );
                    }

                    if (email != null) {
                        headers.add(USER_EMAIL_HEADER, email);
                    }

                    if (role != null) {
                        headers.add(USER_ROLE_HEADER, role);
                    }

                    /*
                     * Optional:
                     * If downstream services don't need the token,
                     * you can remove Authorization before forwarding.
                     *
                     * headers.remove(HttpHeaders.AUTHORIZATION);
                     */
                })
                .build();

        return exchange.mutate()
                .request(mutatedRequest)
                .build();
    }

    private String extractUserId(Jwt jwt) {
        List<String> possibleClaims = List.of(
                "userId",
                "user_id",
                "id",
                "sub"
        );

        return possibleClaims.stream()
                .map(jwt::getClaimAsString)
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }

    private String extractRole(Jwt jwt) {
        String role = jwt.getClaimAsString("role");

        if (role != null) {
            return normalizeRole(role);
        }

        Object rolesClaim = jwt.getClaims().get("roles");

        if (rolesClaim instanceof String rolesString) {
            return normalizeRole(rolesString);
        }

        if (rolesClaim instanceof Collection<?> rolesCollection && !rolesCollection.isEmpty()) {
            Object firstRole = rolesCollection.iterator().next();

            if (firstRole != null) {
                return normalizeRole(firstRole.toString());
            }
        }

        return null;
    }

    private String normalizeRole(String role) {
        return role.replace("ROLE_", "");
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }


}
