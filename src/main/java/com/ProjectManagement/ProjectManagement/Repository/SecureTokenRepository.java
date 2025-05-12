package com.ProjectManagement.ProjectManagement.Repository;
import com.ProjectManagement.ProjectManagement.Entity.SecureToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SecureTokenRepository extends JpaRepository<SecureToken, Long> {
    SecureToken findByToken(String token);
    List<SecureToken> findAllByUserUsername(String username);
    Optional<SecureToken> findFirstByUserUsernameOrderByIdDesc(String username);

}