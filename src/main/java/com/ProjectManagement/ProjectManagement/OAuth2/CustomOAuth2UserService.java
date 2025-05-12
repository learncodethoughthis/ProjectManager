package com.ProjectManagement.ProjectManagement.OAuth2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private static final Logger logger = LoggerFactory.getLogger(CustomOAuth2UserService.class);

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        logger.info("Loading OAuth2User from provider: {}",
                userRequest.getClientRegistration().getRegistrationId());

        OAuth2User user = super.loadUser(userRequest);

        // Log attributes to debug
        user.getAttributes().forEach((key, value) ->
                logger.info("OAuth2 attribute: {} = {}", key, value));

        return user;
    }
}
