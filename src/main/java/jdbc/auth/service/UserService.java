package jdbc.auth.service;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import jdbc.auth.entity.User;
import jdbc.auth.exception.EmailExistsException;
import jdbc.auth.form.UserRegisterationForm;
import jdbc.auth.repository.RoleRepository;
import jdbc.auth.repository.UserRepository;

@Service
public class UserService {

	@Autowired
	private UserRepository repository;

	@Autowired
	private RoleRepository roleRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	public User registerNewUserAccount(UserRegisterationForm registerationForm) throws EmailExistsException {

		User user = repository.findByEmail(registerationForm.getEmail().trim());

		if (user != null) {
			throw new EmailExistsException(
					"There is an account with that email adress: " + registerationForm.getEmail());
		}

		user = new User();
		user.setFirstName(registerationForm.getFirstName());
		user.setLastName(registerationForm.getLastName());
		user.setPassword(passwordEncoder.encode(registerationForm.getPassword()));
		user.setEmail(registerationForm.getEmail());
		user.setEnabled(true);
		user.setRoles(Arrays.asList(roleRepository.findByName("ROLE_USER")));
		return repository.save(user);
	}

	public List<User> findAll() {
		return repository.findAll();
	}
}
