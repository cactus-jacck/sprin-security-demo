package com.aayush.spring_security_demo.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller
{
    @GetMapping("/")
    public String helloWorld()
    {
        return "Hello World";
    }
}
