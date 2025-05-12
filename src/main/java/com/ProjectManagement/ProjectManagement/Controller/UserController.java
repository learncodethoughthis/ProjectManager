package com.ProjectManagement.ProjectManagement.Controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user/api")
public class UserController {

    @GetMapping("/dashboard")
    @PreAuthorize("hasAnyRole('MEMBER', 'MANAGER')")
    public ResponseEntity<String> userDashboard() {
        return ResponseEntity.ok("Welcome to User Dashboard");
    }
}
