package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.TestBase;
import com.lprevidente.cve2docker.entity.vo.dockerhub.SearchTagVO;
import com.lprevidente.cve2docker.entity.vo.dockerhub.SourceRepositoryVO;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class DockerHubServiceTest extends TestBase {

  @Autowired private DockerHubService service;

  @Test
  public void searchReposWithPage() {
    assertDoesNotThrow(
        () -> {
          final var searchRepoVO = service.searchRepos("cve-", 100, 1);
          assertNotNull(searchRepoVO);
          assertFalse(searchRepoVO.getResults().isEmpty());
        });
  }

  @Test
  public void searchRepos() {
    assertDoesNotThrow(
        () -> {
          var text = "cve-";
          final var searchRepoVO = service.searchRepos(text, 1, 1);
          final var repos = service.searchRepos(text);
          assertNotNull(repos);
          assertFalse(repos.isEmpty());
          assertEquals(searchRepoVO.getCount(), repos.size());
        });
  }

  @Test
  public void getURLDockerfile() {
    assertEquals(
        "https://hub.docker.com/v2/repositories/jrrdev/cve-2017-5638/dockerfile",
        service.getURLDockerfile("jrrdev", "cve-2017-5638"));
  }

  @Test
  public void getGithubSourceRepository() {
    final var source = service.getGitHubSourceRepository("vulnerables/cve-2014-0160");
    assertNotNull(source);
    assertEquals("Github", source.getProvider());
    assertEquals("opsxcq", source.getOwner());
    assertEquals("exploit-CVE-2014-0160", source.getRepository());
  }

  @Test
  public void getTags() {
    assertDoesNotThrow(
        () -> {
          final var tags = service.searchTags("php", "7.0.0");
          assertNotNull(tags);
        });
  }
}
