package com.lprevidente.cve2docker;

import com.lprevidente.cve2docker.entity.pojo.ExploitType;
import com.lprevidente.cve2docker.exception.InputException;
import com.lprevidente.cve2docker.service.SystemCve2Docker;
import com.lprevidente.cve2docker.utility.Utils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Date;

@ConditionalOnProperty(
    prefix = "command.line.runner",
    value = "enabled",
    havingValue = "true",
    matchIfMissing = true)
@Component
@Slf4j
public class CommandLineExecutor implements CommandLineRunner {

  @Autowired
  private SystemCve2Docker system;

  @Override
  public void run(String... args) throws InputException {
    if (args.length == 0) throw new InputException("No Input Provided");

    switch (args[0]) {
      case "--edb-id":
        if (args.length == 1) throw new InputException("No edbID provided");
        for (int i = 1; i < args.length; i++) {
          try {
            system.genConfigurationFromExploit(Long.parseLong(args[i]), false);
          } catch (Exception e) {
            log.warn(e.getMessage());
          }
        }
        break;
      case "--gen-all":
        Date startDate = null;
        Date endDate = null;
        var types = new ArrayList<ExploitType>();
        boolean removeConfig = false;
        try {
          for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
              case "--start-date":
                i++;
                if (i == args.length) throw new InputException("No start date provided");
                else startDate = Utils.fromStringToDate(args[i]);
                break;
              case "--end-date":
                i++;
                if (i == args.length) throw new InputException("No end date provided");
                else endDate = Utils.fromStringToDate(args[i]);
                break;
              case "--remove-config":
                removeConfig = true;
                break;
              default:
                types.add(ExploitType.valueOf(args[i].toUpperCase()));
                break;
            }
          }
          system.genConfigurations(startDate, endDate, removeConfig, types);
        } catch (Exception e) {
          log.error("Error: {}", e.getMessage());
        }
        break;
      default:
        throw new InputException("No such command: "+args[0]);
    }
  }
}
