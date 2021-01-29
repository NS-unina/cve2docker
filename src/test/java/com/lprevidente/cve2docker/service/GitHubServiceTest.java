package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.TestBase;
import com.lprevidente.cve2docker.entity.model.ExploitConfiguration;
import com.lprevidente.cve2docker.entity.vo.github.RepoVO;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import javax.transaction.Transactional;

import static org.junit.jupiter.api.Assertions.*;

public class GitHubServiceTest extends TestBase {
  @Autowired private GitHubService service;

  @Test
  public void getRepoInformation() {
    assertDoesNotThrow(
        () -> {
          var repo = service.getRepositoryInformation("vulhub", "vulhub");
          assertNotNull(repo);
          assertEquals(87699760L, repo.getId());
          assertEquals("vulhub", repo.getName());
          assertEquals("vulhub/vulhub", repo.getFull_name());
        });
  }

  @Test
  public void getAllExplConfInRepo() {
    assertDoesNotThrow(
        () -> {
          var repo = service.findConfigurations("vulhub", "vulhub");
          assertFalse(repo.isEmpty());
          repo.forEach(
              config -> {
                assertNotNull(config.getCve());
                assertNotNull(config.getRepository());
                assertNotNull(config.getAuthor());
                assertNotNull(config.getType());
                assertNotNull(config.getRepositoryID());
                assertNotNull(config.getPath());
              });
        });
  }
}
