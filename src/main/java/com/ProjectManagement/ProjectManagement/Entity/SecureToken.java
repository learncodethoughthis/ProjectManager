package com.ProjectManagement.ProjectManagement.Entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Data
public class SecureToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String token;

    private LocalDateTime expiredAt;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
}