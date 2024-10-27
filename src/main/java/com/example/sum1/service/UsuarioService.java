package com.example.sum1.service;

import com.example.sum1.exception.ResourceNotFoundException;
import com.example.sum1.model.Role;
import com.example.sum1.model.Usuario;
import com.example.sum1.repository.UsuarioRepository;
import java.util.Optional; 
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.Valid;


import java.util.List;

@Validated
@Service
public class UsuarioService {

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private PasswordEncoder passwordEncoder; 

     private void validarUsuario(Usuario usuario) {
        if (usuario.getNombre() == null || usuario.getNombre().isEmpty()) {
            throw new IllegalArgumentException("El nombre es obligatorio.");
        }
        if (usuario.getApellido() == null || usuario.getApellido().isEmpty()) {
            throw new IllegalArgumentException("El apellido es obligatorio.");
        }
        if (usuario.getUsername() == null || usuario.getUsername().isEmpty()) {
            throw new IllegalArgumentException("El nombre de usuario es obligatorio.");
        }
        if (usuario.getPassword() == null || usuario.getPassword().isEmpty()) {
            throw new IllegalArgumentException("La contraseña es obligatoria.");
        }
        if (usuario.getEmail() == null || usuario.getEmail().isEmpty()) {
            throw new IllegalArgumentException("El correo electrónico es obligatorio.");
        }
        if (usuario.getRol() == null) {
            throw new IllegalArgumentException("El rol es obligatorio.");
        }
    }

    // Crear o registrar un nuevo usuario
    public Usuario registrarUsuario(@Valid Usuario usuario) {
        validarUsuario(usuario);
        usuario.setPassword(passwordEncoder.encode(usuario.getPassword()));
        return usuarioRepository.save(usuario);
    }

    // Cambia el retorno del método para que devuelva un Optional<Usuario>
    public Optional<Usuario> buscarPorUsername(String username) {
        return usuarioRepository.findByUsername(username);
    }

    // Buscar usuario por su email
    public Usuario buscarPorEmail( String email) {
        return usuarioRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Correo no encontrado: " + email));
    }

    // Verificar si existe un usuario con el username dado
    public Boolean existePorUsername(String username) {
        return usuarioRepository.existsByUsername(username);
    }

    // Verificar si existe un usuario con el email dado
    public Boolean existePorEmail(String email) {
        return usuarioRepository.existsByEmail(email);
    }

    // Obtener todos los usuarios
    public List<Usuario> obtenerTodosLosUsuarios() {
        return usuarioRepository.findAll();
    }

    // Verificar si el usuario es administrador
    public boolean esAdmin(String username) {
        Usuario usuario = buscarPorUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("Usuario no encontrado: " + username));
        return usuario.getRol() == Role.ROLE_ADMIN; 
    }

    // Actualizar un usuario
    public Usuario actualizarUsuario(Long id, @Valid Usuario usuarioActualizado) {
        Usuario usuario = usuarioRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Usuario no encontrado con ID: " + id));

        usuario.setUsername(usuarioActualizado.getUsername());

        if (!usuarioActualizado.getPassword().equals(usuario.getPassword())) {
            usuario.setPassword(passwordEncoder.encode(usuarioActualizado.getPassword()));
        }

        usuario.setEmail(usuarioActualizado.getEmail());
        usuario.setNombre(usuarioActualizado.getNombre());
        usuario.setApellido(usuarioActualizado.getApellido());
        usuario.setRol(usuarioActualizado.getRol());
        return usuarioRepository.save(usuario);
    }

    // Eliminar un usuario por su ID
    public void eliminarUsuario(Long id) {
        Usuario usuario = usuarioRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Usuario no encontrado con ID: " + id));
        usuarioRepository.delete(usuario);
    }
}
