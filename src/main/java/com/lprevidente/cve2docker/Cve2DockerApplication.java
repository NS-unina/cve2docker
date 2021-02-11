package com.lprevidente.cve2docker;

import com.lprevidente.cve2docker.service.SystemCve2Docker;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@Slf4j
public class Cve2DockerApplication implements CommandLineRunner {

  public static void main(String[] args) {
    SpringApplication.run(Cve2DockerApplication.class, args);
  }

  @Autowired private SystemCve2Docker system;

  @Override
  @SneakyThrows
  public void run(String... args) {
    if (args.length == 0) log.warn("No Input Provided");

    if (args.length >= 1) {
      if (args[0].equals("-edbID")) {
        if (args.length == 1) log.warn("No edbID provided");
        for (int i = 1; i < args.length; i++) {
          log.debug("args: {}", i);
          system.genConfigurationFromExploit(args[i]);
        }
      } else log.warn("No such command: {}", args[0]);
    }
  }
}
