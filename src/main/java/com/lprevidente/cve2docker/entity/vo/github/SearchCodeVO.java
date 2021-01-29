package com.lprevidente.cve2docker.entity.vo.github;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class SearchCodeVO {
  private Integer total_count;
  private Boolean incomplete_results;
  private List<FileVO> items;
}
