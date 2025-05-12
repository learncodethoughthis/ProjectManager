package com.ProjectManagement.ProjectManagement.Mailing;

import com.ProjectManagement.ProjectManagement.Entity.User;
import org.springframework.web.util.UriComponentsBuilder;

public class LoginVerificationEmailContext extends AbstractEmailContext{
    private String token;

    @Override
    public <T> void init(T context) {
        User user = (User) context;
        put("Name", user.getName());
        setTemplateLocation("login-verification");
        setSubject("Verify Your Login");
        setFrom("enysalsyrus@gmail.com");
        setTo(user.getEmail());
    }

    public void setToken(String token) {
        this.token = token;
        put("token", token);
    }

    public void buildVerificationUrl(final String baseURL, final String token) {
        final String verificationUrl = UriComponentsBuilder.fromUriString(baseURL)
                .path("/api/auth/login/verify")
                .queryParam("token", token)
                .toUriString();
        put("verificationURL", verificationUrl);
    }
}
