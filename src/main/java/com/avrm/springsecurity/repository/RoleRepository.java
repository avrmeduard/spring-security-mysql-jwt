package com.avrm.springsecurity.repository;

import com.avrm.springsecurity.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);
    Boolean existByUsername(String username);
    Boolean existEmail(String email);
}
