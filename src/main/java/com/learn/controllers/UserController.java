package com.learn.controllers;

import com.learn.models.User;
import com.learn.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@RequestMapping("/users")
@Controller
public class UserController {

    @Autowired
    private UserService userService;
    //allusers
    @GetMapping("/listUser")
//    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @ResponseBody
    public List<User> getAllUsers(){

        return userService.getAllUsers();
    }


    @GetMapping("/userPage")
//    @PreAuthorize("hasRole('ADMIN') || hasRole('USER') ")
    String userPage(){
        return "home";
    }


    //return single user
    @GetMapping("/{username}")
    public User getUser(@PathVariable("username") String username){

        return this.userService.getUser(username);
    }
    //add
    @PostMapping("/")
    public User add(@RequestBody User user){
        return this.userService.addUser(user);
    }
}
