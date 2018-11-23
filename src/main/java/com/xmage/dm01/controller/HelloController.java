package com.xmage.dm01.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "hello")
public class HelloController {

	@Value("${lbs.gis.message:test}")
	private String message = "HelloKitty";
	
	@RequestMapping(value = "say")
	public String sayHello(){
		return "Hello boy.Welcome here!";
	}

	
	@RequestMapping("/gis")
	public String lbsGis(Map<String, Object> model){
		model.put("message", this.message);
		return "lbsgis";
	}

}

