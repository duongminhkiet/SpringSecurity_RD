package com.zmk.security.test.service;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.zmk.security.test.helper.ComponentHelper;
import com.zmk.security.test.object.Authority;
import com.zmk.security.test.object.CustomeUserDetails;
import com.zmk.security.test.object.User;
import com.zmk.security.test.repository.UserRepository;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    //private static final Logger log = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ComponentHelper commonHelper;
    
//    @Override
    public UserDetails loadUserByUsername1(String username1) throws UsernameNotFoundException {
    	
    	if(username1.equalsIgnoreCase("ad")) {
    		return new CustomeUserDetails(commonHelper.createUserAdmin());
    	}else {
            User user = userRepository.findByUsername1(username1);

            if (user == null) {
               throw new UsernameNotFoundException("User not found.");
            }

            //log.info("loadUserByUsername() : {}", username);

            return new CustomeUserDetails(user);
    	}
    	

    }
	@Override
	@Transactional
	public UserDetails loadUserByUsername(String username1) throws UsernameNotFoundException {
		
		User user;
		if(username1.equalsIgnoreCase("ad")) {
			user = commonHelper.createUserAdmin();
		}else {
			user = userRepository.findByUsername1(username1);

	            if (user == null) {
	               throw new UsernameNotFoundException("User not found.");
	            }
		}


		Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
		Set<Authority> roles = user.getAuthorities();
		for (Authority role : roles) {
			grantedAuthorities.add(new SimpleGrantedAuthority(role.getName().toString()));
		}

		return new org.springframework.security.core.userdetails.User(user.getUsername1(), user.getPassword1(),
				grantedAuthorities);
	}
}
