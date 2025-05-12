package com.ProjectManagement.ProjectManagement.Service;

import com.ProjectManagement.ProjectManagement.Mailing.EmailService;
import com.ProjectManagement.ProjectManagement.Mailing.LoginVerificationEmailContext;
import com.ProjectManagement.ProjectManagement.Repository.UserRepository;
import com.ProjectManagement.ProjectManagement.Repository.SecureTokenRepository;
import com.ProjectManagement.ProjectManagement.Repository.RoleRepository;
import com.ProjectManagement.ProjectManagement.Entity.User;
import com.ProjectManagement.ProjectManagement.Entity.SecureToken;
import com.ProjectManagement.ProjectManagement.Entity.Role;
import com.ProjectManagement.ProjectManagement.Mailing.RegistrationVerificationEmailContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
public class UserAccountService {

    private static final Logger logger = LoggerFactory.getLogger(UserAccountService.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private EmailService emailService;

    @Autowired
    private SecureTokenRepository secureTokenRepository;

    @Autowired
    private UserDetailsService userDetailsService;

    @Value("${site.base.url.https}")
    private String baseURL;

    public void register(User user) throws Exception {
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            logger.warn("Registration failed: Email already exists: {}", user.getEmail());
            throw new IllegalArgumentException("Email already exists");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setVerified(false);
        Role memberRole = roleRepository.findByName("MEMBER")
                .orElseThrow(() -> new IllegalStateException("MEMBER role not found"));
        Set<Role> roles = new HashSet<>();
        roles.add(memberRole);
        user.setRoles(roles);
        userRepository.save(user);
        logger.info("User registered: {}", user.getUsername());
        sendRegistrationConfirmationEmail(user);
    }

    @Transactional
    public void sendRegistrationConfirmationEmail(User user) {
        try {
            // Create token first and ensure it's saved
            SecureToken secureToken = createSecureToken(user);

            // Double-check token was saved
            SecureToken savedToken = secureTokenRepository.findByToken(secureToken.getToken());
            if (savedToken == null) {
                logger.error("CRITICAL ERROR: Token was not saved to database for user: {}", user.getUsername());
                throw new RuntimeException("Failed to save verification token to database");
            }

            // Now send the email with the verified token
            RegistrationVerificationEmailContext emailContext = new RegistrationVerificationEmailContext();
            emailContext.init(user);
            emailContext.setToken(secureToken.getToken());
            emailContext.buildVerificationUrl(baseURL, secureToken.getToken());

            emailService.sendMail(emailContext);
            logger.info("Verification email sent to: {} with token: {}", user.getEmail(), secureToken.getToken());
        } catch (Exception e) {
            logger.error("Failed to send verification email to: {}", user.getEmail(), e);
            throw new RuntimeException("Failed to process registration: " + e.getMessage(), e);
        }
    }


    public void sendLoginVerificationEmail(User user) {
        SecureToken secureToken = createSecureToken(user);
        LoginVerificationEmailContext emailContext = new LoginVerificationEmailContext();
        emailContext.init(user);
        emailContext.setToken(secureToken.getToken());
        emailContext.buildVerificationUrl(baseURL, secureToken.getToken());
        try {
            emailService.sendMail(emailContext);
            logger.info("Login verification email sent to: {}", user.getEmail());
        } catch (Exception e) {
            logger.error("Failed to send login verification email to: {}", user.getEmail(), e);
        }
    }

    @Transactional
    public SecureToken createSecureToken(User user) {
        logger.info("Creating secure token for user: {}", user.getUsername());

        try {
            // Create token object
            SecureToken secureToken = new SecureToken();
            secureToken.setToken(UUID.randomUUID().toString());
            secureToken.setExpiredAt(LocalDateTime.now().plusHours(24));
            secureToken.setUser(user);

            // Save token and flush to ensure it's written to DB
            SecureToken savedToken = secureTokenRepository.saveAndFlush(secureToken);
            logger.info("Token created and saved: {}", savedToken.getToken());

            return savedToken;
        } catch (Exception e) {
            logger.error("Error creating secure token", e);
            throw e;
        }
    }

    @Transactional
    public SecureToken verifyUser(String token) {
        logger.info("Verifying token: {}", token);

        SecureToken secureToken = secureTokenRepository.findByToken(token);

        if (secureToken == null) {
            logger.error("Token not found in database: {}", token);

            // Log the count of tokens for debugging
            logger.info("Total tokens in database: {}", secureTokenRepository.count());
            return null;
        }

        logger.info("Token found for user: {}", secureToken.getUser().getUsername());

        if (secureToken.getExpiredAt().isBefore(LocalDateTime.now())) {
            logger.warn("Token expired: {}", token);
            secureTokenRepository.delete(secureToken);
            return null;
        }

        User user = secureToken.getUser();
        user.setVerified(true);
        userRepository.save(user);

        // Don't delete token just yet for debugging
        // secureTokenRepository.delete(secureToken);

        logger.info("User verified successfully: {}", user.getUsername());
        return secureToken;
    }

    public User saveUser(User user) {
        return userRepository.save(user);
    }

    public Optional<User> findUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public User registerSsoUser(User user) throws Exception {
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            // If user exists, just return the existing user
            User existingUser = userRepository.findByEmail(user.getEmail()).get();
            if (!existingUser.isVerified()) {
                existingUser.setVerified(true);
                userRepository.save(existingUser);
            }
            return existingUser;
        }

        // For SSO users, we don't have a password, so generate a random one
        String randomPassword = UUID.randomUUID().toString();
        user.setPassword(passwordEncoder.encode(randomPassword));
        user.setVerified(true); // SSO users are pre-verified

        Role memberRole = roleRepository.findByName("MEMBER")
                .orElseThrow(() -> new IllegalStateException("MEMBER role not found"));
        Set<Role> roles = new HashSet<>();
        roles.add(memberRole);
        user.setRoles(roles);

        userRepository.save(user);
        logger.info("SSO User registered: {}", user.getUsername());
        return user;
    }

    @Transactional
    public User findOrCreateSsoUser(String email, String name) {
        logger.info("Finding or creating SSO user for email: {}", email);

        if (email == null || email.trim().isEmpty()) {
            logger.error("Cannot create SSO user: email is null or empty");
            throw new IllegalArgumentException("Email cannot be null or empty");
        }

        return userRepository.findByEmail(email)
                .map(existingUser -> {
                    // User exists - log details
                    logger.info("Existing user found for SSO email: {} with ID: {}",
                            email, existingUser.getId());

                    // Ensure user is verified
                    if (!existingUser.isVerified()) {
                        existingUser.setVerified(true);
                        logger.info("Marking existing user as verified: {}", email);
                        return userRepository.save(existingUser);
                    }
                    return existingUser;
                })
                .orElseGet(() -> {
                    // Create new user from SSO info
                    logger.info("Creating new user from SSO for email: {}", email);

                    User newUser = new User();
                    newUser.setEmail(email);
                    newUser.setUsername(email); // Use email as username
                    newUser.setName(name != null ? name : "User");
                    newUser.setVerified(true);

                    // Generate random password for SSO users
                    String randomPassword = UUID.randomUUID().toString();
                    newUser.setPassword(passwordEncoder.encode(randomPassword));

                    // Assign MEMBER role
                    Role memberRole = roleRepository.findByName("MEMBER")
                            .orElseThrow(() -> {
                                logger.error("MEMBER role not found in database");
                                return new IllegalStateException("MEMBER role not found");
                            });

                    Set<Role> roles = new HashSet<>();
                    roles.add(memberRole);
                    newUser.setRoles(roles);

                    User savedUser = userRepository.save(newUser);
                    logger.info("New SSO user created with ID: {}", savedUser.getId());
                    return savedUser;
                });
    }

    public SecureTokenRepository getSecureTokenRepository() {
        return secureTokenRepository;
    }

    public UserDetailsService getUserDetailsService() {
        return userDetailsService;
    }
}