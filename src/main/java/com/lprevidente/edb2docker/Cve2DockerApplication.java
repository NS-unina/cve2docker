package com.lprevidente.edb2docker;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@Slf4j
public class Cve2DockerApplication {

  public static void main(String[] args) {
    SpringApplication.run(Cve2DockerApplication.class, args);
  }
}
