package com.mahmoudzain1.config.Security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class JWTAuthenticationConverter implements Converter<Jwt, CustomAuthentication> {


    @Override
    public CustomAuthentication convert(Jwt source) {
        List<GrantedAuthority> authorities = List.of(()-> "read");
        String Role = source.getClaims().get("Roles").toString();
        return new CustomAuthentication(source ,  authorities , Role);
    }
}
