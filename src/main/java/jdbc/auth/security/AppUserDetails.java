package jdbc.auth.security;

import java.util.Collection;
import java.util.HashSet;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jdbc.auth.entity.User;

//It executes 2nd to create UserDetails object for the user 
public class AppUserDetails implements UserDetails {

	private static final long serialVersionUID = 2213172634517672852L;
	private User users;
	private String password;

	public AppUserDetails() {

	}

	public AppUserDetails(User users, String password) {
		super();
		this.users = users;
		this.password = password;
	}

	public User getUsers() {
		return users;
	}

	public void setUsers(User users) {
		this.users = users;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return new HashSet(this.users.getRoles());
	}

	@Override
	public String getPassword() {
		// TODO Auto-generated method stub
		return this.users.getPassword();
	}

	@Override
	public String getUsername() {
		// TODO Auto-generated method stub
		return this.users.getUsername();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isEnabled() {
		// TODO Auto-generated method stub
		return false;
	}

}
