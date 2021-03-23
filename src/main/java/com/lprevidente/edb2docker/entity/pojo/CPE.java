package com.lprevidente.edb2docker.entity.pojo;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.util.Arrays;
import java.util.regex.Pattern;

@Getter
@Setter
@NoArgsConstructor
public class CPE {
  private String cpeVersion;
  private Part part;
  private String vendor;
  private String product;
  private Version version;
  private String update;
  private String edition;
  private String language;

  // RegEx for CPE URI 2.3
  private static final Pattern PATTERN_CPE_URI_2_3 =
      Pattern.compile(
          "cpe:2\\.3:[aho\\*\\-](:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!\"#$$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^`\\{\\|}~]))+(\\?*|\\*?))|[\\*\\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\\*\\-]))(:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!\"#$$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^`\\{\\|}~]))+(\\?*|\\*?))|[\\*\\-])){4}");

  public CPE(String cpeVersion, Part part, String vendor, String product, Version version) {
    this.cpeVersion = cpeVersion;
    this.part = part;
    this.vendor = vendor;
    this.product = product;
    this.version = version;
  }

  public static CPE parse(String toParse) throws Exception {
    if (!PATTERN_CPE_URI_2_3.matcher(toParse).matches())
      throw new Exception(String.format("Error parsing CPE from '%s'", toParse));

    CPE cpe = new CPE();
    String[] cpeSplit = toParse.split(":");
    cpe.setCpeVersion(cpeSplit[1]);
    cpe.setPart(cpeSplit[2]);
    cpe.setVendor(cpeSplit[3]);
    cpe.setProduct(cpeSplit[4]);
    cpe.setVersion(cpeSplit[5].equals("*") ? null : Version.parse(cpeSplit[5]));
    cpe.setUpdate(fromStarToNull(cpeSplit[6]));
    cpe.setEdition(fromStarToNull(cpeSplit[7]));
    cpe.setLanguage(fromStarToNull(cpeSplit[8]));
    return cpe;
  }

  public String toCpeString() {
    final var list =
        Arrays.asList(
            "cpe",
            this.cpeVersion,
            getPartString(),
            this.vendor,
            this.product,
            fromNullToStar(this.version.toString()),
            fromNullToStar(this.update),
            fromNullToStar(this.edition),
            fromNullToStar(this.language),
            "*",
            "*",
            "*",
            "*");

    return StringUtils.join(list, ":");
  }

  public void setPart(String part) {
    switch (part) {
      case "a":
        this.part = CPE.Part.APPLICATION;
        break;
      case "h":
        this.part = CPE.Part.HARDWARE;
      case "o":
        this.part = CPE.Part.OPERATING_SYSTEM;
    }
  }

  public String getPartString() {
    switch (this.part) {
      case APPLICATION:
        return "a";
      case HARDWARE:
        return "h";
      case OPERATING_SYSTEM:
        return "o";
    }
    return null;
  }

  private static String fromStarToNull(String text) {
    return text.equals("*") ? null : text;
  }

  private static String fromNullToStar(String text) {
    return text == null ? "*" : text;
  }

  public enum Part {
    APPLICATION,
    HARDWARE,
    OPERATING_SYSTEM
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;

    if (!(o instanceof CPE)) return false;

    CPE cpe = (CPE) o;

    return new EqualsBuilder()
        .append(cpeVersion, cpe.cpeVersion)
        .append(part, cpe.part)
        .append(vendor, cpe.vendor)
        .append(product, cpe.product)
        .append(version, cpe.version)
        .append(update, cpe.update)
        .append(edition, cpe.edition)
        .append(language, cpe.language)
        .isEquals();
  }

  @Override
  public int hashCode() {
    return new HashCodeBuilder(17, 37)
        .append(cpeVersion)
        .append(part)
        .append(vendor)
        .append(product)
        .append(version)
        .append(update)
        .append(edition)
        .append(language)
        .toHashCode();
  }
}
