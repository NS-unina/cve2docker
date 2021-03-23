package com.lprevidente.edb2docker.entity.vo.dockerhub;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class SearchRepoVO extends SearchVO {
  private List<ResultVO> results;

  @Getter
  @Setter
  @NoArgsConstructor
  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class ResultVO {
    private String repo_name;
    private String short_description;
    private Long star_count;
    private Long pull_count;
    private String repo_owner;
  }

}
