package com.lprevidente.cve2docker.entity.pojo;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class FilePojo {
  private String name;
  private String contentBase64;
  private Type type;
  private List<FilePojo> children;

  public FilePojo(String name, String contentBase64, Type type) {
    this.name = name;
    this.contentBase64 = contentBase64;
    this.type = type;
  }

  public String getContentDecoded() throws IOException {
    if (this.contentBase64 != null)
      return IOUtils.toString(
          Base64.getMimeDecoder().decode(this.contentBase64), StandardCharsets.UTF_8.name());
    return null;
  }

  public enum Type {
    FILE,
    DIR
  }
}
