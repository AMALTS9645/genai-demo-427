 // code-start
package com.example.loginapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Service;
import org.springframework.stereotype.Repository;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@SpringBootApplication
public class LoginAPIApplication {

    public static void main(String[] args) {
        SpringApplication.run(LoginAPIApplication.class, args);
    }

    // UserRepository interface for Spring Data JPA
    @Repository
    public interface UserRepository extends CrudRepository<User, String> {
    }

    // UserDetailsService implementation for Spring Security
    @Service
    public class UserDetailsServiceImpl implements UserDetailsService {

        @Autowired
        private UserRepository userRepository;

        @Autowired
        private PasswordEncoder passwordEncoder;

        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
            User user = userRepository.findByUsername(username);
            if (user == null) {
                throw new UsernameNotFoundException("User not found");
            }
            return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), user.isEnabled());
        }
    }

    // SecurityConfig for Spring Security configuration
    @Configuration
    @EnableWebSecurity
    public class SecurityConfig extends WebSecurityConfigurerAdapter {

        private final UserDetailsService userDetailsService;

        @Autowired
        public SecurityConfig(UserDetailsService userDetailsService) {
            this.userDetailsService = userDetailsService;
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(userDetailsService);
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .antMatchers("/login", "/logout").permitAll()
                    .anyRequest().authenticated()
                .and()
                .formLogin()
                    .loginPage("/login")
                    .defaultSuccessUrl("/home", "https://example.com/")
                    .failureUrl("/login?error")
                    .permitAll()
                .and()
                .logout()
                    .permitAll();
        }
    }

    // LoginController for handling login requests
    @RestController
    @RequestMapping("/api/login")
    public class LoginController {

        private final AuthenticationManager authenticationManager;

        @Autowired
        public LoginController(AuthenticationManager authenticationManager) {
            this.authenticationManager = authenticationManager;
        }

        /**
         * Handles login requests.
         *
         * @param request Request object containing username and password.
         * @return A ResponseEntity containing the authentication token or error message.
         */
        @PostMapping("/authenticate")
        public ResponseEntity<String> authenticate(@RequestBody LoginRequest request) {
            try {
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());
                Authentication authentication = authenticationManager.authenticate(authenticationToken);
                if (authentication.isAuthenticated()) {
                    return ResponseEntity.ok("Authentication successful");
                } else {
                    return ResponseEntity.status(401).body("Authentication failed");
                }
            } catch (Exception e) {
                return ResponseEntity.status(401).body("Authentication failed: " + e.getMessage());
            }
        }
    }

    // LoginRequest class for representing login request data
    public class LoginRequest {

        private String username;
        private String password;

        public LoginRequest(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }
// code-end