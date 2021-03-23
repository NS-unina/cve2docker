package com.lprevidente.edb2docker.entity.vo.nist;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class ConfigurationsVO {
  private String CVE_data_version;
  private List<NodeConfigurationVO> nodes;
}
