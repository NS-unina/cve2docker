package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.entity.pojo.ExploitDB;
import com.lprevidente.cve2docker.exception.GenerationException;
import lombok.NonNull;

/** The interface that every service that generate a configuration must implement */
public interface IGenerateService {

  boolean canHandle(@NonNull ExploitDB exploitDB);

  void genConfiguration(@NonNull ExploitDB exploit, boolean removeConfig)
      throws GenerationException;
}
