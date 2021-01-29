package com.lprevidente.cve2docker.entity.model;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.OneToOne;
import javax.validation.constraints.NotBlank;

@Getter
@Setter
@Entity
public class GeneratedConfig extends ExploitConfiguration {

  @NotBlank
  @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
  private Dockerfile dockerfile;

  public GeneratedConfig(@NotBlank CVE cve, @NotBlank Dockerfile dockerfile) {
    this.dockerfile = dockerfile;
    setCve(cve);
  }

  public GeneratedConfig(
      @NotBlank CVE cve,
      @NotBlank Dockerfile dockerfile,
      @NotBlank String author,
      @NotBlank String repository) {
    this.dockerfile = dockerfile;
    setCve(cve);
    setAuthor(author);
    setRepository(repository);
  }
}
