package com.lprevidente.cve2docker.entity.vo.github;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class RepoVO {
  private Long id;
  private String name;
  private String full_name;
  private UserVO owner;
}
