package com.joy.securitypractice.user.domain.repository;

import com.joy.securitypractice.common.domain.repository.BaseReposiotory;
import com.joy.securitypractice.user.domain.entity.PermissionEntity;
import com.joy.securitypractice.user.domain.entity.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface PermissionRepository extends JpaRepository<PermissionEntity,Long>, BaseReposiotory<PermissionEntity> {
    @Query("select p from PermissionEntity p where p.role.id = :roleId")
    List<PermissionEntity> findAllByRoleId(Long roleId);
}
