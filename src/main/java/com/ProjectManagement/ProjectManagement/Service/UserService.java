package com.ProjectManagement.ProjectManagement.Service;

import com.ProjectManagement.ProjectManagement.Entity.Role;
import com.ProjectManagement.ProjectManagement.Entity.User;
import com.ProjectManagement.ProjectManagement.Repository.RoleRepository;
import com.ProjectManagement.ProjectManagement.Repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    @Lazy
    private PasswordEncoder passwordEncoder;

    // Check if a user exists by email
    public boolean existsByEmail(String email) {
        return userRepository.findByEmail(email).isPresent();
    }

    // Find user by email
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    // Create a new user from OAuth2 provider
    @Transactional
    public User createOAuth2User(String email, String name, String provider) {
        logger.info("Creating new user from OAuth2: {}, provider: {}", email, provider);

        // Create new user
        User user = new User();
        user.setEmail(email);

        // Generate username from email (you might want a more sophisticated approach)
        String username = email.split("@")[0] + "_" + provider;
        int counter = 1;

        // Make sure username is unique
        while (userRepository.findByUsername(username).isPresent()) {
            username = email.split("@")[0] + "_" + provider + counter;
            counter++;
        }

        user.setUsername(username);
        user.setName(name != null ? name : "User");
        user.setVerified(true); // OAuth2 users are pre-verified

        // Generate a secure random password
        String randomPassword = UUID.randomUUID().toString();
        user.setPassword(passwordEncoder.encode(randomPassword));

        // Mark as OAuth2 user
        user.setOauth2Provider(provider);
        user.setOauth2ProviderId(email);

        // Assign default role
        Role memberRole = roleRepository.findByName("MEMBER")
                .orElseThrow(() -> new RuntimeException("MEMBER role not found"));

        Set<Role> roles = new HashSet<>();
        roles.add(memberRole);
        user.setRoles(roles);

        // Save the user
        User savedUser = userRepository.save(user);
        logger.info("Created new user with ID: {}, username: {}", savedUser.getId(), savedUser.getUsername());

        return savedUser;
    }
}