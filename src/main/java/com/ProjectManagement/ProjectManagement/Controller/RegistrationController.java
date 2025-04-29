package com.ProjectManagement.ProjectManagement.Controller;

import com.ProjectManagement.ProjectManagement.DTO.AuthResponse;
import com.ProjectManagement.ProjectManagement.Entity.SecureToken;
import com.ProjectManagement.ProjectManagement.Entity.User;
import com.ProjectManagement.ProjectManagement.Service.UserAccountService;
import com.ProjectManagement.ProjectManagement.Security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/register")
public class RegistrationController {

    @Autowired
    private UserAccountService userAccountService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserDetailsService userDetailsService;

    @PostMapping
    public ResponseEntity<String> register(@RequestBody User user) {
        try {
            userAccountService.register(user);
            return ResponseEntity.ok("Registration successful. Please check your email for verification.");
        }catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/verify")
    public ResponseEntity<?> verify(@RequestParam("token") String token) {
        if (userAccountService.verifyUser(token)) {
            // Find the user associated with the token
            SecureToken secureToken = userAccountService.getSecureTokenRepository().findByToken(token);
            if (secureToken == null) {
                return ResponseEntity.badRequest().body("Invalid token.");
            }
            User user = secureToken.getUser();
            // Generate JWT
            UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
            String jwt = jwtUtil.generateToken(userDetails);
            // Return JWT for frontend to use
            return ResponseEntity.ok(new AuthResponse(jwt));
        }
        return ResponseEntity.badRequest().body("Invalid or expired token.");
    }

}