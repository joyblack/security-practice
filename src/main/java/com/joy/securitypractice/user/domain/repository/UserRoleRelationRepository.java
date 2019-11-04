package com.joy.securitypractice.user.domain.repository;

import com.joy.securitypractice.common.domain.repository.BaseReposiotory;
import com.joy.securitypractice.user.domain.entity.UserEntity;
import com.joy.securitypractice.user.domain.entity.UserRoleRelationEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface UserRoleRelationRepository extends JpaRepository<UserRoleRelationEntity,Long>, BaseReposiotory<UserRoleRelationEntity> {

    List<UserRoleRelationEntity> findAllByUser(UserEntity user);

}
