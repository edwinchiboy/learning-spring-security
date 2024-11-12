package com.in28minutes.learn_spring_security.resources.basic;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.sql.DataSource;

@Configuration
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)

public class BasicAuthSecurityConfiguration {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> {
         requests.requestMatchers("/users").hasRole("USER");
            requests.requestMatchers("/admin/**").hasRole("ADMIN");


            ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl) requests.anyRequest()).authenticated();
        });
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults());
        http
            .csrf(AbstractHttpConfigurer::disable);  // Disables CSRF using lambda
        http.headers().frameOptions().sameOrigin();
        return http.build();
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                    .allowedMethods("*")
                    .allowedOrigins("http://localhost:3000");

            }
        };
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        var user = User.withUsername("in28minutes")
            .password("dummy")
            .passwordEncoder(str -> passwordEncoder().encode(str))
           // .password("{noop}dummy")
            .roles("USER")
            .build();

        var admin = User.withUsername("admin")
//            .password("{noop}dummy")
            .password("dummy")
            .passwordEncoder(str -> passwordEncoder().encode(str))
            .roles("ADMIN")
            .build();

        var adminUser = User.withUsername("adminUser")
//            .password("{noop}dummy")
            .password("dummy")
            .passwordEncoder(str -> passwordEncoder().encode(str))            .roles("ADMIN","USER")
            .build();
        var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);

        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);
        jdbcUserDetailsManager.createUser(adminUser);

        return jdbcUserDetailsManager;
    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//        var user = User.withUsername("in28minutes")
//            .password("{noop}dummy")
//            .roles("USER")
//            .build();
//
//        var admin = User.withUsername("admin")
//            .password("{noop}dummy")
//            .roles("ADMIN")
//            .build();
//        return new InMemoryUserDetailsManager(user, admin);
//    }

    @Bean
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
            .setType(EmbeddedDatabaseType.H2)
            .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION).build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
