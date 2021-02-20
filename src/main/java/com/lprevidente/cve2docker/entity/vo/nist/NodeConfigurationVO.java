package com.lprevidente.cve2docker.entity.vo.nist;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class NodeConfigurationVO {
  private String operator;
  private List<CpeMatchVO> cpe_match;
}
