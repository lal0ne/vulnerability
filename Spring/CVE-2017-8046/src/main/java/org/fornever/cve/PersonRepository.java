package org.fornever.cve;

import org.springframework.data.repository.PagingAndSortingRepository;

public interface PersonRepository extends PagingAndSortingRepository<EntityPerson, Long> {

}
