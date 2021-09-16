package jdbc.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class JdbcAuthenticationApplication {

	public static void main(String[] args) {
		SpringApplication.run(JdbcAuthenticationApplication.class, args);
		System.out.println("application is started");
	}	
}
