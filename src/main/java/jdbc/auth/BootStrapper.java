package jdbc.auth;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import jdbc.auth.entity.Privilege;
import jdbc.auth.entity.Role;
import jdbc.auth.entity.User;
import jdbc.auth.repository.PrivilegeRepository;
import jdbc.auth.repository.RoleRepository;
import jdbc.auth.repository.UserRepository;

@Component
public class BootStrapper implements ApplicationListener<ContextRefreshedEvent> {

	boolean alreadySetup = false;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private RoleRepository roleRepository;

	@Autowired
	private PrivilegeRepository privilegeRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Override
	@Transactional
	public void onApplicationEvent(ContextRefreshedEvent event) {

		if (alreadySetup)
			return;
		Privilege readPrivilege = createPrivilegeIfNotFound("READ_PRIVILEGE");
		Privilege writePrivilege = createPrivilegeIfNotFound("WRITE_PRIVILEGE");

		List<Privilege> adminPrivileges = Arrays.asList(readPrivilege, writePrivilege);
		createRoleIfNotFound("ROLE_ADMIN", adminPrivileges);
		createRoleIfNotFound("ROLE_DBA", adminPrivileges);
		createRoleIfNotFound("ROLE_USER", Arrays.asList(readPrivilege));

		Role adminRole = roleRepository.findByName("ROLE_ADMIN");
		User admin = userRepository.findByEmail("admin@someorg.com");
		if (admin == null) {
			admin = new User();
			admin.setFirstName("Admin");
			admin.setLastName("Head");
			admin.setPassword(passwordEncoder.encode("test"));
			admin.setEmail("admin@someorg.com");
			admin.setRoles(Arrays.asList(adminRole));
			admin.setEnabled(true);
			userRepository.save(admin);
		}
		Role dbaRole = roleRepository.findByName("ROLE_DBA");
		User dba= userRepository.findByEmail("dba@someorg.com");
		if (dba == null) {
			dba = new User();
			dba.setFirstName("DB");
			dba.setLastName("Admin");
			dba.setPassword(passwordEncoder.encode("test"));
			dba.setEmail("dba@someorg.com");
			dba.setRoles(Arrays.asList(dbaRole));
			dba.setEnabled(true);
			userRepository.save(dba);
		}

		alreadySetup = true;
	}

	@Transactional
	Privilege createPrivilegeIfNotFound(String name) {

		Privilege privilege = privilegeRepository.findByName(name);
		if (privilege == null) {
			privilege = new Privilege(name);
			privilegeRepository.save(privilege);
		}
		return privilege;
	}

	@Transactional
	Role createRoleIfNotFound(String name, Collection<Privilege> privileges) {

		Role role = roleRepository.findByName(name);
		if (role == null) {
			role = new Role(name);
			role.setPrivileges(privileges);
			roleRepository.save(role);
		}
		return role;
	}
}