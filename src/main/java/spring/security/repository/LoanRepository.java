package spring.security.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import spring.security.model.Loans;
import java.util.List;

@Repository
public interface LoanRepository extends CrudRepository<Loans, Long> {
	List<Loans> findByCustomerIdOrderByStartDtDesc(long customerId);
}
