package com.zmk.security.test.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.zmk.security.test.object.Authority;

public interface AuthorityRepository extends JpaRepository<Authority, Long>{
	public Authority findByName(String name);
}
