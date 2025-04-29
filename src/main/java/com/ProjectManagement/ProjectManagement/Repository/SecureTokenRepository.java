package com.ProjectManagement.ProjectManagement.Repository;
import com.ProjectManagement.ProjectManagement.Entity.SecureToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecureTokenRepository extends JpaRepository<SecureToken, Long>{
    SecureToken findByToken(String token);
    Long removeByToken(final String token);

}
