package com.zmk.security.test.config;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Component
@Order(2)
public class RequestResponseLoggingFilter implements Filter {
	Logger logger = LoggerFactory.getLogger(RequestResponseLoggingFilter.class);
    @Override
    public void doFilter(
      ServletRequest request, 
      ServletResponse response, 
      FilterChain chain) throws IOException, ServletException {
 
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        logger.info(
          "------------RequestResponseLoggingFilter--------> Logging Request  {} : {}", req.getMethod(), 
          req.getRequestURI());
        chain.doFilter(request, response);
        logger.info(
          "------------RequestResponseLoggingFilter--------> Logging Response :{}", 
          res.getContentType());
    }

    // other methods
}