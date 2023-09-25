package com.cos.jwt.repository;

import com.cos.jwt.model.Users;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Users, Long> {
    public Users findByUsername(String username);
}
