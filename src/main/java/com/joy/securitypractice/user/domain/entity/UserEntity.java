package com.joy.securitypractice.user.domain.entity;

import lombok.Data;
import lombok.ToString;

import javax.persistence.*;

@Data
@ToString
@Entity
@Table(name="all_user")
public class UserEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String loginName;

    @Column(nullable = false)
    private String password;
}
