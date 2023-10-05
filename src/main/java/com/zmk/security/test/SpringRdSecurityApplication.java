package com.zmk.security.test;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.zmk.security.test.config.PasswordEnconderTest;
import com.zmk.security.test.object.Authority;
import com.zmk.security.test.object.AuthorityType;
import com.zmk.security.test.object.User;
import com.zmk.security.test.repository.AuthorityRepository;
import com.zmk.security.test.repository.UserRepository;

@SpringBootApplication
public class SpringRdSecurityApplication implements CommandLineRunner {

	public static void main(String[] args) {
		SpringApplication.run(SpringRdSecurityApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		createDatatest2();
	}
//	@Bean
//	public PasswordEncoder passwordEncoder(){
//	    return new PasswordEnconderTest();
//	}
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	UserRepository userRepository;

	@Autowired
	AuthorityRepository authorityRepository;

	private void createDatatest2() {

		List<User> listUsers = userRepository.findAll();
		List<Authority> listAuthorities = authorityRepository.findAll();
		if(listUsers != null && listUsers.size() >0 && listAuthorities != null && listAuthorities.size() >0) {
			
		}else {
//			Authority admin = new Authority(AuthorityType.ADMIN);
//			Authority admin1 = new Authority(AuthorityType.ADMIN1);
//			Authority admin2 = new Authority(AuthorityType.ADMIN2);
//			Authority manager1 = new Authority(AuthorityType.MANAGER1);
//			Authority manager2 = new Authority(AuthorityType.MANAGER2);
//			Authority user = new Authority(AuthorityType.USER);
			Authority admin = new Authority(AuthorityType.ROLE_ADMIN);
			Authority admin1 = new Authority(AuthorityType.ROLE_ADMIN1);
			Authority admin2 = new Authority(AuthorityType.ROLE_ADMIN2);
			Authority manager1 = new Authority(AuthorityType.ROLE_MANAGER1);
			Authority manager2 = new Authority(AuthorityType.ROLE_MANAGER2);
			Authority user = new Authority(AuthorityType.ROLE_USER);
			authorityRepository.saveAll(Arrays.asList(admin, admin1, admin2, manager1, manager2, user));//save all roles

			String passString = passwordEncoder.encode("123");

			
			User adminUser = new User();
			adminUser.setPassword1(passString);
			adminUser.setUsername1("admin");
			userRepository.save(adminUser); //save user 
			adminUser.getAuthorities().addAll(Arrays.asList(admin, admin1, admin2, manager1, manager2, user));// add all roles into user
			userRepository.save(adminUser);//update user after add roles

			User admin1User = new User();
			admin1User.setPassword1(passString);
			admin1User.setUsername1("admin1");
			userRepository.save(admin1User);
			admin1User.getAuthorities().addAll(Arrays.asList(admin1, manager1, manager2, user));
			userRepository.save(admin1User);

			User admin2User = new User();
			admin2User.setPassword1(passString);
			admin2User.setUsername1("admin2");
			userRepository.save(admin2User);
			admin2User.getAuthorities().addAll(Arrays.asList(admin2, manager1, manager2, user));
			userRepository.save(admin2User);

			User manager1User = new User();
			manager1User.setPassword1(passString);
			manager1User.setUsername1("manager1");
			userRepository.save(manager1User);
			manager1User.getAuthorities().addAll(Arrays.asList(manager1, user));
			userRepository.save(manager1User);

			User manager2User = new User();
			manager2User.setPassword1(passString);
			manager2User.setUsername1("manager2");
			userRepository.save(manager2User);
			manager2User.getAuthorities().addAll(Arrays.asList(manager2, user));
			userRepository.save(manager2User);

			User userUser = new User();
			userUser.setPassword1(passString);
			userUser.setUsername1("user");
			userRepository.save(userUser);
			userUser.getAuthorities().addAll(Arrays.asList(user));
			userRepository.save(userUser);
		}
		
		

	}

}
