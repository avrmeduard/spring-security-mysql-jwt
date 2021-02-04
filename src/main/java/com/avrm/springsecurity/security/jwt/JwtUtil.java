package com.avrm.springsecurity.security.jwt;

import com.avrm.springsecurity.security.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    @Value("${avrm.app.jwtSecret}")
    private String jwtSecret;

    @Value("${avrm.app.jwtExpirationMs}")
    private String jwtExpirationMs;

    public String generateToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder()
                   .setSubject(userPrincipal.getUsername())
                   .setIssuedAt(new Date())
                   .setExpiration(new Date(new Date().getTime() + jwtExpirationMs))
                   .signWith(SignatureAlgorithm.HS512, jwtSecret)
                   .compact();

    }

    public String getUsernameFromJwtToken(String token) {
        return Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody().getSubject();
    }


}
