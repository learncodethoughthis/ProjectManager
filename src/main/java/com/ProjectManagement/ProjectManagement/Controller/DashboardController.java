package com.ProjectManagement.ProjectManagement.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {

    @GetMapping("/user/dashboard")
    @PreAuthorize("hasAnyRole('MEMBER', 'MANAGER')")
    public String userDashboard(Model model, Authentication authentication) {
        model.addAttribute("username", authentication.getName());
        return "user-dashboard";
    }

    @GetMapping("/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminDashboard(Model model, Authentication authentication) {
        model.addAttribute("username", authentication.getName());
        return "admin-dashboard";
    }
}