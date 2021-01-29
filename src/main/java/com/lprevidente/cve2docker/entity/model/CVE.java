package com.lprevidente.cve2docker.entity.model;

import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Entity
@Table(name = "cve")
public class CVE {

  @Id private String id;

  @ManyToMany(fetch = FetchType.LAZY, cascade = CascadeType.MERGE)
  @JoinTable(
      name = "cve_exploit",
      joinColumns = @JoinColumn(name = "cve_id"),
      inverseJoinColumns = @JoinColumn(name = "exploit_id"))
  private List<ExploitDefinition> exploits = new ArrayList<>();

  @OneToMany(mappedBy = "cve", fetch = FetchType.LAZY, cascade = CascadeType.MERGE)
  private List<ExploitConfiguration> configurations = new ArrayList<>();

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;

    if (!(o instanceof CVE)) return false;

    CVE cve = (CVE) o;

    return new EqualsBuilder().append(id, cve.id).isEquals();
  }

  @Override
  public int hashCode() {
    return new HashCodeBuilder(17, 37).append(id).toHashCode();
  }
}
