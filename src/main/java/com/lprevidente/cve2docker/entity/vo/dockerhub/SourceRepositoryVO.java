package com.lprevidente.cve2docker.entity.vo.dockerhub;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class SourceRepositoryVO {
  private MetaVO meta;
  private List<ObjectVO> objects;

  @Getter
  @Setter
  @NoArgsConstructor
  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class MetaVO {
    private Integer limit;
    private String next;
    private Integer offset;
    private String previous;
    private Integer total_count;
  }

  @Getter
  @Setter
  @NoArgsConstructor
  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class ObjectVO {
    private String image;
    private String owner;
    private String provider;
    private String repository;

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;

      if (!(o instanceof ObjectVO)) return false;

      ObjectVO objectVO = (ObjectVO) o;

      return new EqualsBuilder()
          .append(owner, objectVO.owner)
          .append(provider, objectVO.provider)
          .append(repository, objectVO.repository)
          .isEquals();
    }

    @Override
    public int hashCode() {
      return new HashCodeBuilder(17, 37)
          .append(owner)
          .append(provider)
          .append(repository)
          .toHashCode();
    }
  }
}
