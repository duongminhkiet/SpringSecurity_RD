package com.zmk.security.test.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.zmk.security.test.object.User;

public interface UserRepository extends JpaRepository<User, Long>{
	User findByUsername1(String username1);
}
