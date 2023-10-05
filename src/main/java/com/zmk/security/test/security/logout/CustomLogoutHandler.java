package com.zmk.security.test.security.logout;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
public class CustomLogoutHandler implements LogoutHandler {

//    private final UserCache userCache;
//
//    public CustomLogoutHandler(UserCache userCache) {
//        this.userCache = userCache;
//    }
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//		authentication = SecurityContextHolder.getContext().getAuthentication();
//
//		if (authentication != null) {
//			new SecurityContextLogoutHandler().logout(request, response, authentication);
//		}
		try {
			redirectStrategy.sendRedirect(request, response, "/login1?logout=true");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}