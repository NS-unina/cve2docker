package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.TestBase;
import com.lprevidente.cve2docker.entity.pojo.ExploitType;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.util.Arrays;

@Slf4j
public class SystemCve2DockerTest extends TestBase {

  @Autowired private SystemCve2Docker service;

  @Test
  public void testGenConfigurations() throws IOException {
    service.genConfigurations(null, null, true, Arrays.asList(ExploitType.JOOMLA));
  }
}
