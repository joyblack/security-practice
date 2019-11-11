package com.joy.securitypractice.user.domain.repository;

import com.joy.securitypractice.common.domain.repository.BaseReposiotory;
import com.joy.securitypractice.user.domain.entity.RoleEntity;
import com.joy.securitypractice.user.domain.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<RoleEntity,Long>, BaseReposiotory<RoleEntity> {
    /**
     * 通过名称获取角色信息
     */
    RoleEntity findFirstByName(String name);
}
