package com.lprevidente.cve2docker.repository;

import com.lprevidente.cve2docker.entity.model.CVE;
import com.lprevidente.cve2docker.entity.model.ExploitConfiguration;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ExplConfigRepository extends JpaRepository<ExploitConfiguration, Long> {

}
