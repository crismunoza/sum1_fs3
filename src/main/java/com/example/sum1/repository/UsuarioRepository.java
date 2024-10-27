package com.example.sum1.repository;

import com.example.sum1.model.Role;
import com.example.sum1.model.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UsuarioRepository extends JpaRepository<Usuario, Long> {

    // Método para buscar usuario por username
    Optional<Usuario> findByUsername(String username);

    // Método para buscar usuario por email
    Optional<Usuario> findByEmail(String email);

    // Método para verificar si existe un usuario por username
    Boolean existsByUsername(String username);

    // Método para verificar si existe un usuario por email
    Boolean existsByEmail(String email);

    // Método para buscar usuarios por rol
    List<Usuario> findByRol(Role rol);
}
