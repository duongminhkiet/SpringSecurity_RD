package com.zmk.security.test.helper;
import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.zmk.security.test.object.Authority;
import com.zmk.security.test.object.AuthorityType;
import com.zmk.security.test.object.User;

@Component
public class ComponentHelper {

    @Autowired
    PasswordEncoder passwordEncoder;
    public User createUserAdmin() {

		String passString = passwordEncoder.encode("123");
		Authority admin = new Authority(AuthorityType.ROLE_ADMIN);
		Authority admin1 = new Authority(AuthorityType.ROLE_ADMIN1);
		Authority admin2 = new Authority(AuthorityType.ROLE_ADMIN2);
		Authority manager1 = new Authority(AuthorityType.ROLE_MANAGER1);
		Authority manager2 = new Authority(AuthorityType.ROLE_MANAGER2);
		Authority user1 = new Authority(AuthorityType.ROLE_USER);
		Set<Authority> sAuthorities = new HashSet<>();
		sAuthorities.add(admin);sAuthorities.add(admin1);sAuthorities.add(admin2);sAuthorities.add(manager1);sAuthorities.add(manager2);sAuthorities.add(user1);
		User user = new User();
		user.setUsername1("ad");
		user.setPassword1(passString);
		user.getAuthorities().addAll(sAuthorities);
		return user;
	}
//	public User createUserAdmin() {
//
//		String passString = passwordEncoder.encode("123");
//		Authority admin = new Authority(AuthorityType.ADMIN);
//		Authority admin1 = new Authority(AuthorityType.ADMIN1);
//		Authority admin2 = new Authority(AuthorityType.ADMIN2);
//		Authority manager1 = new Authority(AuthorityType.MANAGER1);
//		Authority manager2 = new Authority(AuthorityType.MANAGER2);
//		Authority user1 = new Authority(AuthorityType.USER);
//		Set<Authority> sAuthorities = new HashSet<>();
//		sAuthorities.add(admin);sAuthorities.add(admin1);sAuthorities.add(admin2);sAuthorities.add(manager1);sAuthorities.add(manager2);sAuthorities.add(user1);
//		User user = new User();
//		user.setUsername1("ad");
//		user.setPassword1(passString);
//		user.getAuthorities().addAll(sAuthorities);
//		return user;
//	}
}
