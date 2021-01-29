package com.lprevidente.cve2docker.repository;

import com.lprevidente.cve2docker.entity.model.CVE;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CVERepository extends JpaRepository<CVE, String> {

  @Override
  Optional<CVE> findById(String cveID);

}
