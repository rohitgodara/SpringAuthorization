package jdbc.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import jdbc.auth.entity.Privilege;

@Repository
public interface PrivilegeRepository extends JpaRepository<Privilege,Long>{

	Privilege findByName(String name);

}
