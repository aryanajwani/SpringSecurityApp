package com.aryan.SpringSecurityApp.config;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.aryan.SpringSecurityApp.service.JWTService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


@Component
public class JWTFilter extends OncePerRequestFilter{

    @Autowired
    JWTService jwtService;

    @Autowired
    UserDetailsService userDetailsService;

    @SuppressWarnings("null")
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authoriation = request.getHeader("Authorization");
        
        if(authoriation!=null && authoriation.startsWith("Bearer ")){
            String jwtToken = authoriation.substring(7);

            try {
                jwtService.extractAllClaims(jwtToken);
                String tokenUsername = jwtService.extractUserName(jwtToken);
                User user = (User) userDetailsService.loadUserByUsername(tokenUsername);

                if(SecurityContextHolder.getContext().getAuthentication() == null){
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }

            catch( Exception e){
                e.printStackTrace();
            }
        }
        filterChain.doFilter(request, response);
    }
    
}
