package com.example.securitydemo.security;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.securitydemo.security.ApplicationUserRole.*;
import static com.example.securitydemo.security.ApplicationUserPermission.*;
/*
* ПОРЯДОК antMatchers ОЧЕНЬ ВАЖЕН ТАК КАК ПРОИСХОДИТ ПЕРЕБОРКА СОВПАДЕНИЙ
* НАПРИМЕР antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name()) ЕСЛИ Я
* УБЕРУ ОПРЕДЕЛЕНИЕ МЕТОДА HTTTP antMatchers("/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())ТО
* ПРИ КОМПИЛЯЦИИ МОЖНО ДАТЬ ПРАВА НЕ ТОМУ ПОЛЬЗОВАТЕЛЮ(в зависимости его расположения)
*
*
* */
@Configuration//конфигурация нужна там где определяются бины
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .antMatchers( "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annaSmith = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password"))
//                .roles(STUDENT.name())// вот как видит spring security role: ROLE_STUDENT
                .authorities(STUDENT.getGrantesAuthorities())
                .build();

        UserDetails linda = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
//                .roles(ADMIN.name())// вот как видит spring security role: ROLE_ADMIN
                .authorities(ADMIN.getGrantesAuthorities())
                .build();

        UserDetails tom = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password123"))
//                .roles(ADMINTRAINEE.name())// вот как видит spring security role: ROLE_ADMINTRAINEE
                .authorities(ADMINTRAINEE.getGrantesAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                annaSmith,
                linda,
                tom
        );
    }
}
