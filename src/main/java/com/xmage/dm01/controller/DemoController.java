package com.xmage.dm01.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(value = "demo")
public class DemoController {

	@Value("${lbs.gis.message:test}")//通过@Value("${属性名}")注解来加载对应的配置属性
	private String message = "HelloKitty";//读取配置信息,如无则默认"test"
	
	
	@RequestMapping("/gis")
	public String lbsGis(Map<String, Object> model){
		model.put("message", this.message);
		return "/lbsgis";
	}

}

