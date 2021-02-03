package com.lprevidente.cve2docker.entity.pojo.docker;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;


@Getter
@Setter
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Service {
  String image;
  String user;
  String restart;
  List<String> ports;
  List<String> volumes;
  Map<String, String> environment;
  List<String> depends_on;
  List<String> links;
  List<String> command;
}
