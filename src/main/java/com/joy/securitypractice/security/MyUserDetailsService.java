package com.joy.securitypractice.security;

import com.joy.securitypractice.user.domain.entity.RoleEntity;
import com.joy.securitypractice.user.domain.entity.UserEntity;
import com.joy.securitypractice.user.domain.entity.UserRoleRelationEntity;
import com.joy.securitypractice.user.domain.repository.RoleRepository;
import com.joy.securitypractice.user.domain.repository.UserRepository;
import com.joy.securitypractice.user.domain.repository.UserRoleRelationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service("userDetailsService")
public class MyUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserRoleRelationRepository userRoleRelationRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<GrantedAuthority> authorityList = new ArrayList<>();
        // from db to get user info.
        UserEntity user = userRepository.findFirstByLoginName(username);
        if(null == user){
            throw new UsernameNotFoundException("user name not exist.");
        }

        // set permission
        List<UserRoleRelationEntity> rs = userRoleRelationRepository.findAllByUser(user);
        for (UserRoleRelationEntity r : rs) {
            System.out.println(r);
            RoleEntity role = r.getRole();
            authorityList.add(new SimpleGrantedAuthority(role.getName()));
        }

        // return UserDetails implements class.
        return new User(username, user.getPassword(), authorityList);
    }
}
