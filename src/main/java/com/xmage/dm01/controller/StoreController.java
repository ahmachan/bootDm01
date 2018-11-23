package com.xmage.dm01.controller;

import java.util.ArrayList;
import java.util.List;

import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.xmage.dm01.model.User;

@RestController
@RequestMapping("/shop")
public class StoreController {

	static final private List<User> customers  = new ArrayList<User>();

	
	@RequestMapping(value = "/{id}", method = RequestMethod.GET, produces = "application/json")
    public User getStoreById(@PathVariable("id") Long id,ModelMap model) { 
		 Long i = id;
		 int ii = Integer.parseInt(String.valueOf(id)); 
		 customers.add(new User(i,"user-"+i+1,20+ii,"gz-"+i+1));

		 User userObj = customers.get(0);
		
		return userObj;
    }

}