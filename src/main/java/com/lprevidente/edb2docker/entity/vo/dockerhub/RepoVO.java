package com.lprevidente.edb2docker.entity.vo.dockerhub;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class RepoVO {
  private String user;
  private String name;
  private String full_description;
}
