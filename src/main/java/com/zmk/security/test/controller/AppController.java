package com.zmk.security.test.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AppController {

    private boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || AnonymousAuthenticationToken.class.isAssignableFrom(authentication.getClass())) {
            return false;
        }
        return authentication.isAuthenticated();
    }
    @RequestMapping(value = "/login1", method = RequestMethod.GET)
    public String login1Page(@RequestParam(value = "error", required = false) String error, 
                            @RequestParam(value = "logout", required = false) String logout,
                            Model model) {
        String errorMessge = null;
        if(error != null) {
            errorMessge = "Username or Password is incorrect !!";
        }
        if(logout != null) {
            errorMessge = "You have been successfully logged out !!";
        }
        model.addAttribute("errorMessge", errorMessge);
        
        if (isAuthenticated()) {
            return "redirect:/home";
        }
        
        return "login2";
    }
    @RequestMapping(value="/", method = RequestMethod.GET)
    public String index (HttpServletRequest request, HttpServletResponse response) {
        if (!isAuthenticated()) {
            return "redirect:/login1";
        }
        return "redirect:/home";
    }
    @RequestMapping(value="/home", method = RequestMethod.GET)
    public String home (HttpServletRequest request, HttpServletResponse response) {
        return "home";
    }
    @RequestMapping(value="/hello", method = RequestMethod.GET)
    public String hello (HttpServletRequest request, HttpServletResponse response) {
        return "hello";
    }
    @RequestMapping(value="/403", method = RequestMethod.GET)
    public String denied403 (HttpServletRequest request, HttpServletResponse response) {
        return "403";
    }
    @RequestMapping(value="/user", method = RequestMethod.GET)
    public String user (HttpServletRequest request, HttpServletResponse response) {
        return "user";
    }
    @RequestMapping(value="/manager1", method = RequestMethod.GET)
    public String manager1 (HttpServletRequest request, HttpServletResponse response) {
        return "manager1";
    }
    @RequestMapping(value="/manager2", method = RequestMethod.GET)
    public String manager2 (HttpServletRequest request, HttpServletResponse response) {
        return "manager2";
    }
    @RequestMapping(value="/admin1", method = RequestMethod.GET)
    public String admin1 (HttpServletRequest request, HttpServletResponse response) {
        return "admin1";
    }
    @RequestMapping(value="/admin2", method = RequestMethod.GET)
    public String admin2 (HttpServletRequest request, HttpServletResponse response) {
        return "admin2";
    }
    @RequestMapping(value="/admin", method = RequestMethod.GET)
    public String admin (HttpServletRequest request, HttpServletResponse response) {
        return "admin";
    }
    @RequestMapping(value="/adminx", method = RequestMethod.GET)
    public String adminx (HttpServletRequest request, HttpServletResponse response) {
        return "adminx";
    }
    
    @PreAuthorize("hasAnyAuthority(@authorityService.getAuthoritiesAdmin)")// authorityService in file DynamicAuthorService.java and other exam in WebSecurityConfig.java
//    @Secured ({"ROLE_ADMIN", "ROLE_ADMIN1"})
//    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN1','ROLE_ADMIN')")
//    @PreAuthorize("hasAuthority('ROLE_ADMIN1') or hasAuthority('ROLE_ADMIN')")
    @RequestMapping(value="/dynamic", method = RequestMethod.GET)
    public String dynamicauthor (HttpServletRequest request, HttpServletResponse response) {
        return "dynamicauthor";
    }
}
