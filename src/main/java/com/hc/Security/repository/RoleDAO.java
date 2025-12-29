package com.hc.Security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.hc.Security.entity.Role;


public interface RoleDAO extends JpaRepository<Role, Long>{
    boolean existsByName(String name);
    Optional<Role> findByName(String name);
}
