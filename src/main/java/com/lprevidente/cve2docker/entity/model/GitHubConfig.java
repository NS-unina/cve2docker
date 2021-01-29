package com.lprevidente.cve2docker.entity.model;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.validation.constraints.NotBlank;

@Getter
@Setter
@Entity
public class GitHubConfig extends ExploitConfiguration {

  @NotBlank private Long repositoryID;

  @NotBlank
  @Enumerated(EnumType.STRING)
  private Type type;

  @NotBlank private String path;

  @Getter
  public enum Type {
    DOCKERFILE,
    DOCKER_COMPOSE;

    public static Type parse(String value) throws Exception {
      switch (value.toLowerCase()) {
        case "dockerfile":
          return DOCKERFILE;
        case "docker-compose":
          return DOCKER_COMPOSE;
        default:
          throw new Exception(String.format("Error parsing CVE from '%s'", value));
      }
    }
  }
}
