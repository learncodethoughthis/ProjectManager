package com.ProjectManagement.ProjectManagement.OAuth2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;

@Controller
@RequestMapping("/oauth2")
public class OAuth2Controller {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2Controller.class);

    /**
     * Redirects to Google OAuth2 login
     */
    @GetMapping("/login/google")
    public String googleLogin() {
        logger.info("Redirecting to Google OAuth2 login");
        return "redirect:/oauth2/authorization/google?action=login";
    }

    /**
     * Redirects to Google OAuth2 for registration
     */
    @GetMapping("/registration/google")
    public String googleRegistration() {
        logger.info("Redirecting to Google OAuth2 for registration");
        return "redirect:/oauth2/authorization/google?action=registration";
    }

    /**
     * REST API endpoint for Google login (returns JSON instead of redirect)
     */
    @GetMapping("/api/login/google")
    @ResponseBody
    public ResponseEntity<?> apiGoogleLogin() {
        logger.info("API request for Google OAuth2 login");
        return ResponseEntity.ok(Map.of(
                "redirectUrl", "/oauth2/authorization/google?action=login"
        ));
    }

    /**
     * REST API endpoint for Google registration (returns JSON instead of redirect)
     */
    @GetMapping("/api/registration/google")
    @ResponseBody
    public ResponseEntity<?> apiGoogleRegistration() {
        logger.info("API request for Google OAuth2 registration");
        return ResponseEntity.ok(Map.of(
                "redirectUrl", "/oauth2/authorization/google?action=registration"
        ));
    }

    /**
     * Debug endpoint to check OAuth2 state
     */
    @GetMapping("/debug")
    @ResponseBody
    public ResponseEntity<?> debugOAuth2(@RequestParam(required = false) String action) {
        logger.info("OAuth2 debug endpoint hit with action: {}", action);
        return ResponseEntity.ok(Map.of(
                "message", "OAuth2 debug endpoint",
                "action", action != null ? action : "none"
        ));
    }
}