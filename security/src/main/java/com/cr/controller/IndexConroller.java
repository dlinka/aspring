package com.cr.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexConroller {

    @GetMapping("/")
    public String index(){
        return "index";
    }

}
