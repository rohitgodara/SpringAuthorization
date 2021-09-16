package jdbc.auth.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	// RoleHierarchy implementation allows ADMIN to access any resource available for admin, user, and guest roles,
	// where as user to access any resource available for user and guest roles.
	@Bean
	public RoleHierarchy roleHierarchy() {
		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
		roleHierarchyImpl.setHierarchy("ROLE_ADMIN > ROLE_USER > ROLE_GUEST");
		return roleHierarchyImpl;
	}

	@Bean
	public PasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}

	@Autowired
	private UserDetailsService userDetailsService;

	// It creates an authProvider strategy
	@Bean
	public DaoAuthenticationProvider authProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService);
		authProvider.setPasswordEncoder(encoder());
		return authProvider;
	}

	// To set authProvider
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authProvider());
	}

	/**
	1. BELOW There are multiple authorization rules specified.
			"Each rule is considered in the order they were declared."
	2. We specified multiple URL patterns that any user can access.
			"Specifically, any user can access a request if the URL starts with '/resources/', equals '/signup', or equals '/about'."
	3. Any URL that starts with "/admin/" will be restricted to users who have the role "ROLE_ADMIN".
			"You will notice that since we are invoking the hasRole method we do not need to specify the "ROLE_" prefix."
	4. Any URL that starts with "/db/" requires the user to have both "ROLE_ADMIN" and "ROLE_DBA".
			"You will notice that since we are using the hasRole expression we do not need to specify the "ROLE_" prefix."
	5. Any URL that has not already been matched on is denied access.
			"This is a good strategy if you do not want to accidentally forget to update your authorization rules." 
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable()
				.authorizeRequests(authorize -> authorize.
						antMatchers("/login", "/register", "/signup").permitAll().
						antMatchers("/admin/**").hasRole("ADMIN").
						antMatchers("/users/**").hasRole("USER").
//						antMatchers("/users/**").access("@webSecurityCustomChecks.check(authentication,request)").
//						antMatchers("/users/**").access("hasRole('ADMIN') and hasRole('USER')").
						antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')").
						anyRequest().denyAll())
				.formLogin().and().httpBasic();
	}

}
