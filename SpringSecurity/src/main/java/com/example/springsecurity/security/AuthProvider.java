package com.example.springsecurity.security;


import java.util.Optional;

//import com.example.mysqldb.domain.Attempts;
//import com.example.mysqldb.domain.User;
//import com.example.mysqldb.services.SecurityUserDetailsService;
import com.example.springsecurity.model.Attempts;
import com.example.springsecurity.model.User;
import com.example.springsecurity.repository.AttemptsRepository;
import com.example.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;


//import com.example.mysqldb.repositories.AttemptsRepository;
//import com.example.mysqldb.repositories.UserRepository;

@Component public class AuthProvider implements AuthenticationProvider {
    private static final int ATTEMPTS_LIMIT = 3;
    @Autowired private SecurityUserDetailsService userDetailsService;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private AttemptsRepository attemptsRepository;
    @Autowired private UserRepository userRepository;

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException  {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        User user = (User) userDetailsService.loadUserByUsername(username);
        if (user != null) {
            if(user.getAccountNonLocked()) {


                boolean isPasswordMatched = passwordEncoder.matches(password, user.getPassword());
                if (isPasswordMatched) {
                    Optional<Attempts>
                            userAttempts = attemptsRepository.findAttemptsByUsername(username);
                    if (userAttempts.isPresent()) {
                        Attempts attempts = userAttempts.get();
                        attempts.setAttempts(0);
                        attemptsRepository.save(attempts);
                    }

                    return new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword(), user.getAuthorities());

                } else {
                    processFailedAttempts(username, user);
                }
            }else{
                throw new LockedException("Account is locked!!");
            }
        }

        return  null;
    }



    private void processFailedAttempts(String username, User user) {
        Optional<Attempts>
                userAttempts = attemptsRepository.findAttemptsByUsername(username);
        if (userAttempts.isEmpty()) {
            Attempts attempts = new Attempts();
            attempts.setUsername(username);
            attempts.setAttempts(1);
            attemptsRepository.save(attempts);
        } else {
            Attempts attempts = userAttempts.get();
            attempts.setAttempts(attempts.getAttempts() + 1);
            attemptsRepository.save(attempts);

            if (attempts.getAttempts() + 1 >
                    ATTEMPTS_LIMIT) {
                user.setAccountNonLocked(false);
                userRepository.save(user);
                throw new LockedException("Too many invalid attempts. Account is locked!!");
            }
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}