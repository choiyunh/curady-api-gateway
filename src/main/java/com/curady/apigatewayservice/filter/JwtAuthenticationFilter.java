package com.curady.apigatewayservice.filter;

import com.curady.apigatewayservice.jwt.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    @Autowired
    private JwtUtil jwtUtil;

    public JwtAuthenticationFilter() {
        super(Config.class);
    }

    public static class Config {
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            final List<String> apiEndpoints = List.of("/auth");

            Predicate<ServerHttpRequest> isApiSecured = r -> apiEndpoints.stream()
                    .noneMatch(uri -> r.getURI().getPath().contains(uri));

            if (!isApiSecured.test(exchange.getRequest())) {
                if (!exchange.getRequest().getHeaders().containsKey("X-AUTH-TOKEN")) {
                    ServerHttpResponse response = exchange.getResponse();
                    response.setStatusCode(HttpStatus.UNAUTHORIZED);

                    return response.setComplete();
                }
                String token = exchange.getRequest().getHeaders().get("X-AUTH-TOKEN").get(0);
                Map<String, Object> userInfo = jwtUtil.getClaims(token);
                if (userInfo == null) {
                    ServerHttpResponse response = exchange.getResponse();
                    response.setStatusCode(HttpStatus.UNAUTHORIZED);

                    return response.setComplete();
                }
                addAuthorizationHeaders(exchange.getRequest(), userInfo);
            }
            return chain.filter(exchange);
        };
    }

    private void addAuthorizationHeaders(ServerHttpRequest request, Map<String, Object> userInfo) {
        request.mutate()
                .header("X-Authorization-Id", userInfo.get("sub").toString())
                .build();
    }
}
