package com.example.sum1.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Entity
@Table(name = "productos")
public class Producto {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull(message = "El nombre del producto es obligatorio")
    @Size(min = 1, max = 100, message = "El nombre del producto debe tener entre 1 y 100 caracteres")
    @Column(nullable = false)
    private String nombre;

    @NotNull(message = "La descripción del producto es obligatoria")
    @Size(min = 1, max = 255, message = "La descripción del producto debe tener entre 1 y 255 caracteres")
    @Column(nullable = false)
    private String descripcion;

    @NotNull(message = "El precio del producto es obligatorio")
    @Min(value = 0, message = "El precio del producto no puede ser negativo")
    @Column(nullable = false)
    private Double precio;

    @NotNull(message = "El stock del producto es obligatorio")
    @Min(value = 0, message = "El stock del producto no puede ser negativo")
    @Column(nullable = false)
    private Integer stock;

    // Getters y setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public String getDescripcion() {
        return descripcion;
    }

    public void setDescripcion(String descripcion) {
        this.descripcion = descripcion;
    }

    public Double getPrecio() {
        return precio;
    }

    public void setPrecio(Double precio) {
        this.precio = precio;
    }

    public Integer getStock() {
        return stock;
    }

    public void setStock(Integer stock) {
        this.stock = stock;
    }
}
