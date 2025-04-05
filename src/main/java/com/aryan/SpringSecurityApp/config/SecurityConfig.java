package com.aryan.SpringSecurityApp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http .authorizeHttpRequests(request -> request
                    .requestMatchers("login", "signup").permitAll()
                    .anyRequest().authenticated())

                // .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable())
                .addFilterBefore(jwtFilter(), BasicAuthenticationFilter.class)
                .build();
    }

    // verification process - provides an Authentication instance
    @Bean
    public AuthenticationProvider authenticationProvider(PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider dao = new DaoAuthenticationProvider();
        dao.setUserDetailsService(userDetailsService);
        dao.setPasswordEncoder(passwordEncoder);
        return dao;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception{
        return config.getAuthenticationManager();
    }

    @Bean 
    public JWTFilter jwtFilter(){
        return new JWTFilter();
    }

    // @Bean
    // public UserDetailsService userDetailsService() {
    // System.out.println("Inside UserDetailsService");
    // UserDetails user1 = User
    // .builder()
    // // .withDefaultPasswordEncoder()
    // .username("aryan")
    // .password("a@123")
    // .roles("ADMIN")
    // .build();

    // UserDetails user2 = User
    // // .withDefaultPasswordEncoder()
    // .builder()
    // .username("sharthak")
    // .password("s@123")
    // .roles("ADMIN")
    // .build();
    // return new InMemoryUserDetailsManager(user1, user2);
    // }
}
