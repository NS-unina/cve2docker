package com.lprevidente.cve2docker.entity.vo.github;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class FileVO {
  private String name;
  private String path;
  private String url;
  private String git_url;
  private String html_url;
  private String type;
  private String content;
  private RepoVO repository;
}
