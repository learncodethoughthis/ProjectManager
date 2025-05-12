package com.ProjectManagement.ProjectManagement.OAuth2;

import com.ProjectManagement.ProjectManagement.Entity.User;
import com.ProjectManagement.ProjectManagement.Security.JwtUtil;
import com.ProjectManagement.ProjectManagement.Service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthenticationSuccessHandler.class);

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();

            // Get user details from OAuth2 provider
            Map<String, Object> attributes = oauth2User.getAttributes();

            // Log attributes for debugging
            logger.info("OAuth2 user attributes: {}", attributes);

            // Get essential information
            String email = (String) attributes.get("email");
            String name = (String) attributes.get("name");

            if (email == null) {
                logger.error("Email not provided by OAuth2 provider");
                response.sendRedirect("/login?error=email_not_provided");
                return;
            }

            // Check if this is a registration request
            boolean isRegistration = request.getParameter("registration") != null &&
                    request.getParameter("registration").equals("true");


                User user;

                if (isRegistration) {
                    // Registration flow
                    if (userService.existsByEmail(email)) {
                        // User already exists, redirect to login
                        logger.info("User with email {} already exists, redirecting to login", email);
                        response.sendRedirect("/login?error=user_exists");
                        return;
                    }

                    // Create new user
                    user = userService.createOAuth2User(email, name, "google");
                    logger.info("Created new user from Google OAuth2: {}", user.getUsername());

                    // Redirect to registration success page
                    response.sendRedirect("/registration-success?provider=google");
                } else {
                    // Login flow
                    user = userService.findByEmail(email)
                            .orElseGet(() -> {
                                // Auto-register if user doesn't exist
                                logger.info("User with email {} not found, auto-registering", email);
                                return userService.createOAuth2User(email, name, "google");
                            });

                    // Generate JWT token
                    String token = jwtUtil.generateToken(user.getUsername());

                    // Redirect to the frontend with token
                    //response.sendRedirect("/login-success?token=" + token);
                    logger.info("Redirecting to SSO endpoint with token for user: {}", user.getUsername());
                    response.sendRedirect("/api/auth/sso?token=" + token);
                }
        }
    }
}