package com.ProjectManagement.ProjectManagement.Controller;

import com.ProjectManagement.ProjectManagement.DTO.AuthResponse;
import com.ProjectManagement.ProjectManagement.Entity.SecureToken;
import com.ProjectManagement.ProjectManagement.Entity.User;
import com.ProjectManagement.ProjectManagement.Repository.SecureTokenRepository;
import com.ProjectManagement.ProjectManagement.Repository.UserRepository;
import com.ProjectManagement.ProjectManagement.Service.UserAccountService;
import com.ProjectManagement.ProjectManagement.Security.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/register")
public class RegistrationController {
    private static final Logger logger = LoggerFactory.getLogger(RegistrationController.class);
    @Autowired
    private UserAccountService userAccountService;
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping
    public ResponseEntity<String> register(@RequestBody User user) throws Exception {
        logger.info("Processing registration for user with email: {}", user.getEmail());

        try {
            userAccountService.register(user);
            logger.info("Registration successful for user: {}", user.getUsername());
            return ResponseEntity.ok("Registration successful. Please check your email for verification.");
        } catch (Exception e) {
            logger.error("Registration failed for user with email: {}", user.getEmail(), e);
            return ResponseEntity.badRequest().body("Registration failed: " + e.getMessage());
        }
    }
    @GetMapping("/verify")
    public ResponseEntity<?> verify(@RequestParam("token") String token) {
        logger.info("EMAIL VERIFICATION ENDPOINT HIT: /register/verify with token: {}", token);

        SecureToken secureToken = userAccountService.verifyUser(token);
        if (secureToken == null) {
            logger.warn("Invalid or expired token: {}", token);
            return ResponseEntity.badRequest().body(new AuthResponse(null, "Invalid or expired token.", null));
        }

        User user = secureToken.getUser();
        if (user == null) {
            logger.warn("User not found for token: {}", token);
            return ResponseEntity.badRequest().body(new AuthResponse(null, "User not found.", null));
        }

        // Get user details for JWT
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        String jwt = jwtUtil.generateToken(userDetails);

        // Set authentication in security context
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);

        // Determine redirect URL based on role
        String redirectUrl = userDetails.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN")) ?
                "/admin/dashboard" : "/user/dashboard";

        logger.info("Email verification successful for user: {}", user.getUsername());

        // Return JWT and redirect URL for frontend
        return ResponseEntity.ok(new AuthResponse(jwt, "Email verified successfully", redirectUrl));
    }



}