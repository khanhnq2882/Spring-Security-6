package spring.security.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import spring.security.model.Customer;
import java.util.Optional;

@Repository
public interface CustomerRepository extends CrudRepository<Customer,Long> {
    Optional<Customer> findByEmail(String email);
}
