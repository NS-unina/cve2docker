package com.lprevidente.cve2docker.entity.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;

@Getter
@Setter
@Entity
@Table(name = "dockerfile")
@NoArgsConstructor
public class Dockerfile {

  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  private Long id;

  @NotBlank private String image;

  @NotBlank private String version;

  private String urlVulnApp;

  private String urlExploit;

  public Dockerfile(@NotBlank String image, @NotBlank String version) {
    this.image = image;
    this.version = version;
  }

  public String generateDockerfile() {
    var builder = new StringBuilder();
    builder.append("FROM ").append(this.image).append(":").append(this.version);
    builder.append("\nENTRYPOINT [\"/bin/bash\"]").append("\nRUN mkdir -p /vulnApp");
    if (this.urlVulnApp != null)
      builder.append("\nADD ").append(this.urlVulnApp).append(" /vulnApp");
    if (this.urlExploit != null)
      builder.append("\nADD ").append(this.urlExploit).append(" /vulnApp");
    return builder.toString();
  }
}
