package com.lprevidente.cve2docker.command;

import org.apache.commons.cli.Option;

public class EdbIDOption {

  public static final Option EDB_ID =
      Option.builder("id")
          .longOpt("edb-id")
          .hasArg(true)
          .numberOfArgs(Option.UNLIMITED_VALUES)
          .desc("The exploitDB ID for which you want to generate the configuration")
          .required(true)
          .build();
}
