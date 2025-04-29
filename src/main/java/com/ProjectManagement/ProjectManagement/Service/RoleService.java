package com.ProjectManagement.ProjectManagement.Service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.*;
import com.ProjectManagement.ProjectManagement.Repository.UserRepository;
import com.ProjectManagement.ProjectManagement.Repository.RoleRepository;
import com.ProjectManagement.ProjectManagement.Entity.Role;
@Service
public class RoleService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    public List<Role> findAll(){
        return roleRepository.findAll();
    }

    public Role findById(int id){
        return roleRepository.findById(id).orElse(null);
    }

    public void delete(int id){
        roleRepository.deleteById(id);
    }

    public void saveRole(Role role){
        roleRepository.save(role);
    }
}
