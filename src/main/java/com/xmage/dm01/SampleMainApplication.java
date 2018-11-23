package com.xmage.dm01;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * 主应用入口
 * @类名:SampleMainApplication
 */
@Controller
@SpringBootApplication
public class SampleMainApplication {

    @ResponseBody
    @RequestMapping(value = "/")
    String home(){
        return "Hello World,Spring Boot in Docker";
    }

    public static void main(String[] args) {
        SpringApplication.run(SampleMainApplication.class,"--server.port=8081");
    }
}