package jdbc.auth.security.custom;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class WebSecurityCustomChecks {

	public boolean check(Authentication authentication, HttpServletRequest request) {
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();
		System.out.println("|||||||||||||||||||||||||||||| \n\n");
		System.out.println(userDetails.getUsername()+" :: User has authorities: " + userDetails.getAuthorities());
		System.out.println(
				"At the time of authorization if we want to perform any check that is not already provided by the spring security so we can create our own custom check here in this class.");
		System.out.println(
				"NOTE:: WebSecurityCustomChecks, is just for testing purpose and not compulsory for the authentication and authorization.");
		System.out.println("\n\n||||||||||||||||||||||||||||||");
		return true;
	}
}
