package com.xmage.dm01.controller;

import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.xmage.dm01.model.User;

@Controller
@RequestMapping("/agent")
public class AgentController {
    
    @RequestMapping(value = "/{id}", method = RequestMethod.GET)
    public String  getUser(@PathVariable Long id,ModelMap model) {     
        model.addAttribute("user",new User(id,"张三",23,"中国广州天河沙东街道"));
        return "/agent/detail";
    }
    
    @RequestMapping(value = "/detail/{id}", method = RequestMethod.GET)
    public String getUser(Model model, @PathVariable("id") Long id) {
        User user = new User();
        user.setId(id);
        user.setName("liuMin");
        user.setAge(23);
        user.setAddress("中国广州天河沙东街道");
        model.addAttribute("user", user);
        return "agent/detail";
    }
    
    @RequestMapping("/list")
    public String  listUser(ModelMap model) {
        List<User> userList = new ArrayList<User>();
        
        for (int i = 0; i <10; i++) {
        	Long ii = (long)(i+1);
            userList.add(new User(ii,"张三"+i,20+i,"中国广州"));
        }
        
        model.addAttribute("users", userList);
        return "/agent/list";
    }
}