package com.lprevidente.cve2docker.entity.vo.nist;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.lprevidente.cve2docker.entity.pojo.CPE;
import com.lprevidente.cve2docker.entity.pojo.Version;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@Setter
@Getter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
@Slf4j
public class CpeMatchVO {
  private Boolean vulnerable;
  private CPE cpe;
  private Version versionStartIncluding;
  private Version versionStartExcluding;
  private Version versionEndIncluding;
  private Version versionEndExcluding;

  @JsonProperty("cpe23Uri")
  public void setCpe(String cpe23Uri) {
    try {
      this.cpe = CPE.parse(cpe23Uri);
    } catch (Exception e) {
      log.error("An exception occurred during analysis: {}", e.getLocalizedMessage());
    }
  }

  @JsonProperty("versionStartIncluding")
  public void setVersionStartIncluding(String versionStartIncluding) {
    try {
      this.versionStartIncluding = Version.parse(versionStartIncluding);
    } catch (Exception e) {
      log.error("An exception occurred during analysis: {}", e.getLocalizedMessage());
    }
  }

  @JsonProperty("versionStartExcluding")
  public void setVersionStartExcluding(String versionStartExcluding) {
    try {
      this.versionStartExcluding = Version.parse(versionStartExcluding);
    } catch (Exception e) {
      log.error("An exception occurred during analysis: {}", e.getLocalizedMessage());
    }
  }

  @JsonProperty("versionEndExcluding")
  public void setVersionEndExcluding(String versionEndExcluding) {
    try {
      this.versionEndExcluding = Version.parse(versionEndExcluding);
    } catch (Exception e) {
      log.error("An exception occurred during analysis: {}", e.getLocalizedMessage());
    }
  }

  @JsonProperty("versionEndIncluding")
  public void setVersionEndIncluding(String versionEndIncluding) {
    try {
      this.versionEndIncluding = Version.parse(versionEndIncluding);
    } catch (Exception e) {
      log.error("An exception occurred during analysis: {}", e.getLocalizedMessage());
    }
  }
}
