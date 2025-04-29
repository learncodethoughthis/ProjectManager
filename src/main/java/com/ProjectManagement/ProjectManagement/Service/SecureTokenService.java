package com.ProjectManagement.ProjectManagement.Service;
import com.ProjectManagement.ProjectManagement.Entity.SecureToken;
public interface SecureTokenService {
    SecureToken createToken();

    void saveSecureToken(SecureToken secureToken);

    SecureToken findByToken(String token);

    void removeToken(SecureToken token);
}
