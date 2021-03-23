package com.lprevidente.edb2docker.command;

import org.apache.commons.cli.Option;

public class GenAllOption {
  public static final Option GEN_ALL =
      Option.builder("a")
          .longOpt("gen-all")
          .hasArg(true)
          .numberOfArgs(Option.UNLIMITED_VALUES)
          .desc("The exploitDB ID for which you want to generate the configuration")
          .required(true)
          .build();

  public static final Option TYPE =
      Option.builder("t")
          .longOpt("type-exploit")
          .hasArg(true)
          .numberOfArgs(1)
          .argName("type")
          .desc("[REQUIRED] The exploit types: wordpress, joomla or php")
          .required(true)
          .build();

  public static final Option START_DATE =
      Option.builder("s")
          .longOpt("start-date")
          .hasArg(true)
          .numberOfArgs(1)
          .argName("yyyy-MM-dd")
          .desc("Date (included) after which the exploit has been published")
          .required(false)
          .build();

  public static final Option END_DATE =
      Option.builder("e")
          .longOpt("end-date")
          .hasArg(true)
          .numberOfArgs(1)
          .argName("yyyy-MM-dd")
          .desc("Date (included) before which the exploit has been published")
          .required(false)
          .build();

  public static final Option REMOVE_CONFIG =
      Option.builder("r")
          .longOpt("remove-config")
          .hasArg(true)
          .argName("true/false")
          .numberOfArgs(1)
          .desc(
              "If true remove the container after it has been tested, with the volumes associated to it. Default: false")
          .required(false)
          .build();
}
