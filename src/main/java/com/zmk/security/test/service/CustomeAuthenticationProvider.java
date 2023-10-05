package com.zmk.security.test.service;

import javax.annotation.Resource;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class CustomeAuthenticationProvider implements AuthenticationProvider {

	@Resource
    UserDetailsService userDetailsService;
    @Override
    public Authentication authenticate(Authentication authentication) 
      throws AuthenticationException {
 
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        
        if (!StringUtils.hasText(username)) {
            throw new BadCredentialsException("invalid login details");
        }
        // get user details using Spring security user details service
        UserDetails user = null;
        try {
            user = userDetailsService.loadUserByUsername(username);// => nơi call Service từ bên thứ 3

        } catch (UsernameNotFoundException exception) {
            throw new BadCredentialsException("invalid login details");
        }
        return createSuccessfulAuthentication(authentication, user);
    }
    private Authentication createSuccessfulAuthentication(final Authentication authentication, final UserDetails user) {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user.getUsername(), authentication.getCredentials(), user.getAuthorities());
        token.setDetails(authentication.getDetails());
        return token;
    }
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
