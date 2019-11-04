package com.joy.securitypractice.user.domain.repository;

import com.joy.securitypractice.common.domain.repository.BaseReposiotory;
import com.joy.securitypractice.user.domain.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity,Long>, BaseReposiotory<UserEntity> {

    UserEntity findFirstByLoginName(String loginName);

}
