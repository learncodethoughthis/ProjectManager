package com.ProjectManagement.ProjectManagement.Controller;

import com.ProjectManagement.ProjectManagement.DTO.AuthResponse;
import com.ProjectManagement.ProjectManagement.DTO.LoginRequest;
import com.ProjectManagement.ProjectManagement.Entity.Role;
import com.ProjectManagement.ProjectManagement.Entity.SecureToken;
import com.ProjectManagement.ProjectManagement.Entity.User;
import com.ProjectManagement.ProjectManagement.Repository.RoleRepository;
import com.ProjectManagement.ProjectManagement.Repository.UserRepository;
import com.ProjectManagement.ProjectManagement.Security.JwtUtil;
import com.ProjectManagement.ProjectManagement.Service.UserAccountService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    @Autowired
    @Lazy
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private UserAccountService userAccountService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserDetailsService userDetailsService;
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            logger.info("Login attempt for username: {}", loginRequest.getUsername());

            // Authenticate the user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            // Find the user directly from UserRepository instead of via token
            User user = userRepository.findByUsername(loginRequest.getUsername())
                    .orElseThrow(() -> {
                        logger.warn("User not found for username: {}", loginRequest.getUsername());
                        return new RuntimeException("User not found");
                    });
            // Send login verification email
            userAccountService.sendLoginVerificationEmail(user);
            logger.info("Login verification email sent to: {}", user.getEmail());
            // Return response indicating email verification is required
            return ResponseEntity.ok(
                    new AuthResponse(null, "Log in successful. Please check your email for verification.", null)
            );
        } catch (Exception e) {
            logger.error("Login failed for username: {}", loginRequest.getUsername(), e);
            return ResponseEntity.badRequest().body(new AuthResponse(null, "Invalid credentials", null));
        }
    }
    @GetMapping("/sso")
    public ResponseEntity<?> handleSSO(
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "token", required = false) String token) {

        logger.info("SSO endpoint hit with code: {}, token: {}",
                (code != null ? "present" : "absent"),
                (token != null ? "present" : "absent"));
        // Case 1: Token is directly provided
        if (token != null && !token.isEmpty()) {
            logger.info("Processing SSO with provided token");
            try {
                // Validate the token
                if (!jwtUtil.validateToken(token)) {
                    logger.warn("Invalid token provided to SSO endpoint");
                    return ResponseEntity.badRequest().body(
                            new AuthResponse(null, "Invalid token", null));
                }

                // Extract username from token
                String username = jwtUtil.extractUsername(token);
                logger.info("Username from token: {}", username);

                // Load user details
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // Set authentication in context
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authToken);

                // Determine redirect URL based on role
                String redirectUrl = userDetails.getAuthorities().stream()
                        .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN")) ?
                        "/admin/dashboard" : "/user/dashboard";

                return ResponseEntity.ok(new AuthResponse(token, "Successfully authenticated", redirectUrl));
            } catch (Exception e) {
                logger.error("Error processing token in SSO endpoint", e);
                return ResponseEntity.badRequest().body(
                        new AuthResponse(null, "Token processing error: " + e.getMessage(), null));
            }
        }
        //OAuth2User in security context
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        logger.info("Authentication object: {}", authentication);
        if (authentication != null) {
            logger.info("Authentication class: {}", authentication.getClass().getName());
            logger.info("Authentication principal class: {}",
                    authentication.getPrincipal() != null ?
                            authentication.getPrincipal().getClass().getName() : "null");
        }
        if (authentication != null && authentication.getPrincipal() instanceof OAuth2User) {
            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
            logger.info("OAuth2User attributes: {}", oAuth2User.getAttributes());
            String email = oAuth2User.getAttribute("email");
            if (email == null) {
                logger.warn("SSO authentication failed - email attribute missing");
                return ResponseEntity.badRequest().body(
                        new AuthResponse(null, "Email not provided by SSO provider", null));
            }
            logger.info("SSO authentication for email: {}", email);
            try {
                // Find or create user based on SSO information
                User user = userAccountService.findOrCreateSsoUser(
                        email,
                        oAuth2User.getAttribute("name")
                );
                // Generate token for automatic login
                UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
                String jwt = jwtUtil.generateToken(userDetails);
                // Set authentication
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authToken);
                // Determine redirect URL based on role
                String redirectUrl = userDetails.getAuthorities().stream()
                        .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN")) ?
                        "/admin/dashboard" : "/user/dashboard";
                logger.info("SSO authentication successful for: {}", email);
                return ResponseEntity.ok(new AuthResponse(jwt, "Successfully authenticated", redirectUrl));
            } catch (Exception e) {
                logger.error("Error processing SSO authentication for email: {}", email, e);
                return ResponseEntity.badRequest().body(
                        new AuthResponse(null, "SSO authentication failed: " + e.getMessage(), null));
            }
        }
        // No token and no OAuth2User found
        logger.warn("SSO authentication failed - no valid authentication method found");
        return ResponseEntity.badRequest().body(
                new AuthResponse(null, "SSO authentication failed - no valid authentication found", null));
    }
    @GetMapping("/login/verify")
    public ResponseEntity<?> verifyLogin(@RequestParam("token") String token) {
        logger.info("Login verification endpoint hit with token: {}", token);

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

        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        String jwt = jwtUtil.generateToken(userDetails);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);

        String redirectUrl = userDetails.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN")) ?
                "/admin/dashboard" : "/user/dashboard";

        logger.info("Login verification successful for user: {}", user.getUsername());
        return ResponseEntity.ok(new AuthResponse(jwt, "Email verified successfully", redirectUrl));
    }

    @GetMapping("/oauth2/register/google")
    public ResponseEntity<?> registerWithGoogle() {
        logger.info("API request to register with Google");
        return ResponseEntity.ok(Map.of(
                "redirectUrl", "/oauth2/registration/google"
        ));
    }

    @GetMapping("/oauth2/login/google")
    public ResponseEntity<?> loginWithGoogle() {
        logger.info("API request to login with Google");
        return ResponseEntity.ok(Map.of(
                "redirectUrl", "/oauth2/authorization/google"
        ));
    }

    @GetMapping("/oauth2/callback")
    public ResponseEntity<?> handleOAuth2Callback(@RequestParam(required = false) String code,
                                                  @RequestParam(required = false) String error) {
        if (error != null) {
            logger.error("OAuth2 callback error: {}", error);
            return ResponseEntity.badRequest().body(Map.of(
                    "error", error
            ));
        }

        logger.info("OAuth2 callback received with code");
        return ResponseEntity.ok(Map.of(
                "message", "Processing OAuth2 authentication"
        ));
    }
}






