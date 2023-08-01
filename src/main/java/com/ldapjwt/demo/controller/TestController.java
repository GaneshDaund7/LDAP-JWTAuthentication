package com.ldapjwt.demo.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test/greet")
public class TestController {

	@GetMapping
	public ResponseEntity<String> Greet()
	{
		return new ResponseEntity<String>("Hello This is Ldap Test",HttpStatus.OK);
	}
}
