package com.lprevidente.edb2docker.entity.vo.nist;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class SearchCpeVO extends SearchVO {
  private ResultCpeVO result = new ResultCpeVO();

  @JsonProperty("products")
  private JsonNode resultTemp;

  public void setResultList(List<CpeMatchVO> cpes){
    this.result.setCpes(cpes);
  }

  @Setter
  @Getter
  @NoArgsConstructor
  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class ResultCpeVO {
    private List<CpeMatchVO> cpes;
  }
}
