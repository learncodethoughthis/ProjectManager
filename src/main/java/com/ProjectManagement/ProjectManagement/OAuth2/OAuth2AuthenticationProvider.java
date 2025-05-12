package com.ProjectManagement.ProjectManagement.OAuth2;

import com.ProjectManagement.ProjectManagement.Entity.User;
import com.ProjectManagement.ProjectManagement.Repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class OAuth2AuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthenticationProvider.class);

    @Autowired
    private UserRepository userRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        logger.debug("Attempting to authenticate: {}", username);

        // First, try to find user by username
        Optional<User> userOptional = userRepository.findByUsername(username);

        // If not found by username, try email
        if (userOptional.isEmpty()) {
            userOptional = userRepository.findByEmail(username);
        }

        if (userOptional.isPresent()) {
            User user = userOptional.get();

            // Check if this is an OAuth2 user trying to login with password
            if (user.isOauth2User()) {
                logger.info("OAuth2 user attempted password login: {}", username);
                throw new BadCredentialsException("Please use your OAuth2 provider to login");
            }
        }

        // Not an OAuth2 user or user not found, let the next provider handle it
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}