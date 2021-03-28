package com.lprevidente.edb2docker.service;

import com.lprevidente.edb2docker.TestBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.junit.jupiter.api.Assertions.*;

public class DockerHubServiceTest extends TestBase {

  @Autowired private DockerHubService service;

  @Test
  public void getTags() {
    assertDoesNotThrow(
        () -> {
          final var tags = service.searchTags("php", "7.0.0");
          assertNotNull(tags);
        });
  }
}
