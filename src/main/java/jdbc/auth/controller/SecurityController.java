package jdbc.auth.controller;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

	@RequestMapping(value = "/username/principal", method = RequestMethod.GET)
	public String currentUserName(Principal principal) {
		return principal.getName();
	}

	@RequestMapping(value = "/username/authentication", method = RequestMethod.GET)
	public String currentUserName(Authentication authentication) {
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();
		System.out.println(userDetails.getUsername()+" :: User has authorities: " + userDetails.getAuthorities());
		return authentication.getName();
	}

	@RequestMapping(value = "/username/request", method = RequestMethod.GET)
	public String currentUserNameSimple(HttpServletRequest request) {
		Principal principal = request.getUserPrincipal();
		return principal.getName();
	}
}
