package com.ProjectManagement.ProjectManagement.Service;

import com.ProjectManagement.ProjectManagement.Entity.SecureToken;
import com.ProjectManagement.ProjectManagement.Repository.SecureTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.util.Base64;

import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import java.time.LocalDateTime;

@Service
public class DefaultSecureTokenService implements SecureTokenService {

    private static BytesKeyGenerator DEFAULT_TOKEN_GENERATOR = KeyGenerators.secureRandom(12);
    @Autowired
    private SecureTokenRepository secureTokenRepository;

    @Value("2800")
    private int tokenValidityInSeconds;

    @Override
    public SecureToken createToken() {
        byte[] tokenBytes = DEFAULT_TOKEN_GENERATOR.generateKey();
        String tokenValue = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        SecureToken secureToken = new SecureToken();
        secureToken.setToken(tokenValue);
        secureToken.setExpiredAt(LocalDateTime.now().plusSeconds(tokenValidityInSeconds));
        this.saveSecureToken(secureToken);
        return secureToken;
    }

    @Override
    public void saveSecureToken(SecureToken secureToken) {
        secureTokenRepository.save(secureToken);
    }

    @Override
    public SecureToken findByToken(String token) {
        return secureTokenRepository.findByToken(token);
    }

    @Override
    public void removeToken(SecureToken token) {
        secureTokenRepository.delete(token);
    }
}
