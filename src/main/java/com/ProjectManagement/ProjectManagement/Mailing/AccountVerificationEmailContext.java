package com.ProjectManagement.ProjectManagement.Mailing;

import org.springframework.web.util.UriComponentsBuilder;
import com.ProjectManagement.ProjectManagement.Entity.User;

public class AccountVerificationEmailContext extends AbstractEmailContext{
    private String token;

    @Override
    public <T> void init(T context) {
        User user = (User) context;
        put("Name", user.getName());
        setTemplateLocation("email-verification");
        setSubject("Complete Your Registration");
        setFrom("enysalsyrus@gmail.com");
        setTo(user.getEmail());
    }

    public void setToken(String token) {
        this.token = token;
        put("token", token);
    }

    public void buildVerificationUrl(final String baseURL, final String token) {
        final String url = UriComponentsBuilder.fromUriString(baseURL)
                .path("/register/verify")
                .queryParam("token", token)
                .toUriString();
        put("verificationURL", url);
    }
}
