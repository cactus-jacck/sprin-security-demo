package com.aayush.spring_security_demo.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller
{
    @GetMapping("/")
    public String helloWorld()
    {
        return "Hello World!";
    }

    @GetMapping("/user")
    public String user()
    {
        return "Hello User";
    }

    @GetMapping("/admin")
    public String admin()
    {
        return "Hello Admin";
    }
}
