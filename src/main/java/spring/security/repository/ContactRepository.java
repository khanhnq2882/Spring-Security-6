package spring.security.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import spring.security.model.Contact;

@Repository
public interface ContactRepository extends CrudRepository<Contact, String> {
	
	
}
