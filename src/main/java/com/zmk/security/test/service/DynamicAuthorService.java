package com.zmk.security.test.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.zmk.security.test.object.Authority;
import com.zmk.security.test.repository.AuthorityRepository;

@Service("authorityService")
public class DynamicAuthorService {

	@Autowired
	AuthorityRepository authorityRepository;
	
	private String authorities;
	public String getAuthoritiesAdmin() {
		String authorities = "";
		List<Authority> listAuthorities = authorityRepository.findAll();
		for(Authority authority : listAuthorities) {
			if(authority.getName().toString().contains("ROLE_ADMIN")) {
				authorities+=authority.getName()+",";
			}
			
		}
		if(authorities != null && authorities.length() >0) {
			authorities = authorities.substring(0, authorities.length()-1);
		}
		System.out.println("XXX=> "+authorities);
		return authorities;
	}
	public String getAuthoritiesString() {
		String authorities = "";
		List<Authority> listAuthorities = authorityRepository.findAll();
		for(Authority authority : listAuthorities) {
			authorities+=authority.getName()+",";
		}
		if(authorities != null && authorities.length() >0) {
			authorities = authorities.substring(0, authorities.length()-1);
		}
		System.out.println(authorities);
		return authorities;
	}
	public List<String> getAuthorities(){
		List<String> list = new ArrayList<String>();
		List<Authority> listAuthorities = authorityRepository.findAll();
		for(Authority authority : listAuthorities) {
			list.add(authority.getName().toString());
			authorities+=authority.getName()+",";
		}
		if(authorities != null && authorities.length() >0) {
			authorities = authorities.substring(0, authorities.length()-1);
		}
		
		return list;
	}
}
