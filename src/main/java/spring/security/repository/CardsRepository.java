package spring.security.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import spring.security.model.Cards;
import java.util.List;

@Repository
public interface CardsRepository extends CrudRepository<Cards, Long> {
	List<Cards> findByCustomerId(long customerId);
}
