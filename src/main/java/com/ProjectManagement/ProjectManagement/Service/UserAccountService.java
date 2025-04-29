package com.ProjectManagement.ProjectManagement.Service;

import com.ProjectManagement.ProjectManagement.Repository.UserRepository;
import com.ProjectManagement.ProjectManagement.Repository.SecureTokenRepository;
import com.ProjectManagement.ProjectManagement.Repository.RoleRepository;
import com.ProjectManagement.ProjectManagement.Entity.User;
import com.ProjectManagement.ProjectManagement.Entity.SecureToken;
import com.ProjectManagement.ProjectManagement.Entity.Role;
import com.ProjectManagement.ProjectManagement.Mailing.AccountVerificationEmailContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Service
public class UserAccountService {
    private static final Logger logger = LoggerFactory.getLogger(UserAccountService.class);
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SecureTokenRepository secureTokenRepository;

    @Autowired RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private EmailService emailService;

    @Value("${site.base.url.https}")
    private String baseURL;

    public void register(User user) throws Exception {
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
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

        sendRegistrationConfirmationEmail(user);
    }

    public void sendRegistrationConfirmationEmail(User user) throws Exception {
        String token = UUID.randomUUID().toString();
        SecureToken secureToken = new SecureToken();
        secureToken.setToken(token);
        secureToken.setUser(user);
        secureToken.setExpiredAt(LocalDateTime.now().plusHours(24));
        secureTokenRepository.save(secureToken);

        AccountVerificationEmailContext emailContext = new AccountVerificationEmailContext();
        emailContext.init(user);
        emailContext.setToken(token);
        emailContext.buildVerificationUrl(baseURL, token);
        logger.debug("Preparing email to: {}, from: {}, subject: {}, URL: {}",
                emailContext.getTo(), emailContext.getFrom(), emailContext.getSubject(),
                emailContext.getContext().get("verificationURL"));
        emailService.sendMail(emailContext);
    }

    public boolean verifyUser(String token) {
        SecureToken secureToken = secureTokenRepository.findByToken(token);
        if (secureToken == null || secureToken.getExpiredAt().isBefore(LocalDateTime.now())) {
            return false;
        }

        User user = secureToken.getUser();
        if (!user.isVerified()) {
            user.setVerified(true);
            userRepository.save(user);
            secureTokenRepository.delete(secureToken);
        }
        return true;
    }

    public SecureTokenRepository getSecureTokenRepository() {
        return secureTokenRepository;
    }
}