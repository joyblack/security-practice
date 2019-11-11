package com.joy.securitypractice.security;

import com.joy.securitypractice.user.domain.entity.PermissionEntity;
import com.joy.securitypractice.user.domain.repository.PermissionRepository;
import com.joy.securitypractice.user.domain.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public class MyPermissionEvaluator implements PermissionEvaluator {
    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PermissionRepository permissionRepository;

    @Override
    public boolean hasPermission(Authentication authentication, Object targetUrl, Object targetPermission) {
        // 获得loadUserByUsername()方法的结果
        User user = (User)authentication.getPrincipal();
        // 获得loadUserByUsername()中注入的角色
        Collection<GrantedAuthority> authorities = user.getAuthorities();

        // 遍历用户所有角色
        for(GrantedAuthority authority : authorities) {
            String roleName = authority.getAuthority();
            Long roleId = roleRepository.findFirstByName(roleName).getId();
            // 得到角色所有的权限
            List<PermissionEntity> permissionList = permissionRepository.findAllByRoleId(roleId);
            // 遍历permissionList
            for(PermissionEntity sysPermission : permissionList) {
                // 获取权限集
                List permissions = Arrays.asList(sysPermission.getPermission().split(","));
                // 如果访问的Url和权限用户符合的话，返回true
                if(targetUrl.equals(sysPermission.getUrl())
                        && permissions.contains(targetPermission)) {
                    return true;
                }
            }

        }

        return false;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        return false;
    }
}
