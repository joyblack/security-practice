package com.joy.securitypractice.user.service;

import com.joy.securitypractice.user.domain.entity.PermissionEntity;
import com.joy.securitypractice.user.domain.repository.PermissionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private PermissionRepository permissionRepository;

    /**
     * 获取指定角色的所有权限
     */
    public List<PermissionEntity> getByRoleId(Integer roleId){
        return permissionRepository.findAllByRoleId(roleId);
    }
}
