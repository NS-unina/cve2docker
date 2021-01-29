package com.lprevidente.cve2docker.entity.vo.nist;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class SearchVO {
  private Integer resultsPerPage;
  private Integer startIndex;
  private Integer totalResults;
}
