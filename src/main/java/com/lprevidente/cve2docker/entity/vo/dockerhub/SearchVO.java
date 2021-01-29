package com.lprevidente.cve2docker.entity.vo.dockerhub;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class SearchVO {
  private Integer count;
  private String next;
  private String previous;
}
