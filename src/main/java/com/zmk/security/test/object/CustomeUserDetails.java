package com.zmk.security.test.object;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class CustomeUserDetails implements UserDetails {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private User user;

    public CustomeUserDetails(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getAuthorities().stream().map(authority -> new SimpleGrantedAuthority(authority.getName().toString())).collect(Collectors.toList());
    }

    public int getId() {
        return user.getId();
    }

    @Override
    public String getPassword() {
        return user.getPassword1();
    }

    @Override
    public String getUsername() {
        return user.getUsername1();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public User getUserDetails() {
        return user;
    }
}