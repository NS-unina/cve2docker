package com.lprevidente.edb2docker;

import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;

public class CommandLineTest {

  @Test
  public void NoOption() {
    SpringApplication.run(Cve2DockerApplication.class);
  }

  @Test
  public void idOptionNoValue() {
    SpringApplication.run(Cve2DockerApplication.class, "--edb-id");
  }

  @Test
  public void help() {
    SpringApplication.run(
        Cve2DockerApplication.class, "-h");
  }

  @Test
  public void GenAllOptionNoValue() {
    SpringApplication.run(
        Cve2DockerApplication.class, "--gen-all", "-t wordpress", "--start-date", "2020-01-01", "-r true" );
  }
}
