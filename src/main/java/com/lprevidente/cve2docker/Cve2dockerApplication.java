package com.lprevidente.cve2docker;

import com.lprevidente.cve2docker.entity.model.ExploitDB;
import com.lprevidente.cve2docker.service.ExploitDBService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Cve2dockerApplication {

  public static void main(String[] args) {
    SpringApplication.run(Cve2dockerApplication.class, args);
  }

}
