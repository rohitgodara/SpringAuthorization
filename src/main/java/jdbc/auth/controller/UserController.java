package jdbc.auth.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jdbc.auth.entity.User;
import jdbc.auth.form.UserRegisterationForm;
import jdbc.auth.service.UserService;

@RestController
public class UserController {

	@Autowired
	private UserService service;

	@PostMapping("signup")
	public String register(@RequestBody UserRegisterationForm registerationForm) {
		try {
			User user = service.registerNewUserAccount(registerationForm);
			if (user != null)
				return "success";
			return "failed";
		} catch (Exception e) {
			return e.getMessage();
		}
	}

	@GetMapping("/users")
	public List<User> users() {
		return service.findAll();
	}

}
