package com.boot.board_240718.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Autowired
    private DataSource dataSource;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll() // 모든 요청 허용
                )
                .csrf(csrf -> csrf.disable()) // CSRF 비활성화
                .formLogin(form -> form.disable()) // 폼 로그인 비활성화
                .httpBasic(httpBasic -> httpBasic.disable()) // HTTP 기본 인증 비활성화
                .logout(logout -> logout.disable()); // 로그아웃 비활성화

        return http.build();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth)
            throws Exception {
        auth.jdbcAuthentication()
                .dataSource(dataSource)
                // 패스워드 암호화 메소드를 스프링에서 관리
                .passwordEncoder(passwordEncoder())
                .usersByUsernameQuery("select username,password,enabled "
                        + "from user "
                        + "where username = ?")
                .authoritiesByUsernameQuery("SELECT username, name " +
                                "FROM user_role ur " +
                                "INNER JOIN USER u " +
                                "ON ur.user_id = u.id " +
                                "INNER JOIN ROLE r " +
                                "ON ur.role_id = r.id "+
                                "where username = ?");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}