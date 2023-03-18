package com.furkanbulut.gateway.filter;

import com.furkanbulut.gateway.util.JwtUtil;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;


@Component

public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Confıg>{

    private final RouteValidator routeValidator;

    private final RestTemplate restTemplate;

    private final JwtUtil jwtUtil;

    public AuthenticationFilter(RouteValidator routeValidator, RestTemplate restTemplate, JwtUtil jwtUtil) {
        super(Confıg.class);
        this.routeValidator = routeValidator;
        this.restTemplate = restTemplate;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public GatewayFilter apply(Confıg config) {
        return ((exchange, chain) -> {
            if (routeValidator.isSecured.test(exchange.getRequest())) {
                //header contains token or not
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new RuntimeException("missing authorization header");
                }
                String authheader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if(authheader!=null && authheader.startsWith("Bearer ")){
                    authheader=authheader.substring(7);
                }
                try{
                    //restTemplate.getForObject("http://AUTHENTICATION-SERVICE//validate?token"+authheader,String.class);

                    jwtUtil.validateToken(authheader);
                }catch (Exception e){
                    throw new RuntimeException("un authorized access o application");
                }
            }
            return chain.filter(exchange);
        });
    }

    public static class Confıg{

    }
}