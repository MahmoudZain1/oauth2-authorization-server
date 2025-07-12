package com.mahmoudzain1.config.Security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;


public class CustomAuthentication extends JwtAuthenticationToken {

    private final String Roles;

    public CustomAuthentication(Jwt jwt, Collection<? extends GrantedAuthority> authorities, String roles) {
        super(jwt, authorities);
       this.Roles = roles;
    }

    public String getRoles() {
        return Roles;
    }
}
