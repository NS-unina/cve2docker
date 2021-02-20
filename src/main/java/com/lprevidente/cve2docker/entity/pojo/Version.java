package com.lprevidente.cve2docker.entity.pojo;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import org.springframework.expression.ParseException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.apache.commons.lang3.StringUtils.*;

/**
 * The Version class can be used to parse a standard version string into its four components,
 * MAJOR.MINOR.BUILD.REVISION.
 */
@Getter
@Setter
@NoArgsConstructor
public class Version implements Comparable<Version> {
  private String rawVersion;
  private String sufix;
  private String major = "0";
  private String minor = "0";
  private String build = "0";
  private String revision = "0";

  private int numberOfComponents;

  /** A pattern to match the standard version format MAJOR.MINOR.BUILD.REVISION. */
  private static Pattern STD_VERSION_PATT =
      Pattern.compile("^(\\d+)(?:\\.([\\d|x|*]+))?(?:\\.([\\d|x|*]+))?(?:\\.([\\d|x|*]+))?(.*)$");

  /**
   * Parses a new Version object from a String.
   *
   * @param toParse The String object to parse.
   * @return A new Version object.
   * @throws Exception When there is an error parsing the String.
   */
  public static Version parse(String toParse) throws ParseException {
    Matcher m = STD_VERSION_PATT.matcher(toParse);

    if (!m.find())
      throw new ParseException(0, String.format("Error parsing version from '%s'", toParse));

    Version v = new Version();
    v.rawVersion = toParse;

    if (isNotEmpty(m.group(1))) v.setMajor(m.group(1));

    if (isNotEmpty(m.group(2))) v.setMinor(m.group(2));

    if (isNotEmpty(m.group(3))) v.setBuild(m.group(3));

    if (isNotEmpty(m.group(4))) v.setRevision(m.group(4));

    if (isNotEmpty(m.group(5))) v.setSufix(m.group(4));

    return v;
  }

  /**
   * Sets the version's MAJOR component.
   *
   * @param toSet The version's MAJOR component.
   * @throws IllegalArgumentException When a null or non-numeric value is given.
   */
  public void setMajor(@NonNull String toSet) throws IllegalArgumentException {
    if (!toSet.matches("[\\d|x|*]+")) throw new IllegalArgumentException("Argument is not numeric");

    if (toSet.equals("x")) toSet = "*";

    if (this.numberOfComponents < 1) this.numberOfComponents = 1;

    this.major = toSet;
  }

  /**
   * Sets the version's MAJOR component.
   *
   * @param toSet The version's MAJOR component.
   */
  public void setMajor(int toSet) {
    setMajor(String.valueOf(toSet));
  }

  /** The version's MAJOR component as an integer. */
  private int getMajorAsInt() {
    return Integer.parseInt(this.major);
  }

  /**
   * Sets the version's MINOR component.
   *
   * @param toSet The version's MINOR component.
   * @throws IllegalArgumentException When a null or non-numeric value is given.
   */
  public void setMinor(@NonNull String toSet) throws IllegalArgumentException {

    if (!toSet.matches("[\\d|x|*]+")) throw new IllegalArgumentException("Argument is not numeric");

    if (toSet.equals("x")) toSet = "*";

    if (this.numberOfComponents < 2) this.numberOfComponents = 2;

    this.minor = toSet;
  }

  /**
   * Sets the version's MINOR component.
   *
   * @param toSet The version's MINOR component.
   */
  public void setMinor(int toSet) {
    setMinor(String.valueOf(toSet));
  }

  /** The version's MINOR component as an integer. */
  private int getMinorAsInt() {
    return Integer.parseInt(this.minor);
  }

  /** The version's BUILD component as an integer. */
  private int getBuildAsInt() {
    return Integer.parseInt(this.build);
  }

  /**
   * Sets the version's BUILD component.
   *
   * @param toSet The version's BUILD component.
   * @throws IllegalArgumentException When a null or non-numeric value is given.
   */
  public void setBuild(@NonNull String toSet) throws IllegalArgumentException {

    if (!toSet.matches("[\\d|x|*]+")) throw new IllegalArgumentException("Argument is not numeric");

    if (toSet.equals("x")) toSet = "*";

    if (this.numberOfComponents < 3) this.numberOfComponents = 3;

    this.build = toSet;
  }

  /**
   * Sets the version's BUILD component.
   *
   * @param toSet The version's BUILD component.
   */
  public void setBuild(int toSet) {
    setBuild(String.valueOf(toSet));
  }

  /** The version's REVISION component as an integer. */
  private int getRevisionAsInt() {
    return Integer.parseInt(this.revision);
  }

  /**
   * Sets the version's REVISION component.
   *
   * @param toSet The version's REVISION component.
   * @throws IllegalArgumentException When a null or non-numeric value is given.
   */
  public void setRevision(@NonNull String toSet) throws IllegalArgumentException {

    if (!toSet.matches("[\\d|x|*]+")) throw new IllegalArgumentException("Argument is not numeric");

    if (toSet.equals("x")) toSet = "*";

    if (this.numberOfComponents < 4) this.numberOfComponents = 4;

    this.revision = toSet;
  }

  /**
   * Sets the version's REVISION component.
   *
   * @param toSet The version's REVISION component.
   */
  public void setRevision(int toSet) {
    setRevision(String.valueOf(toSet));
  }

  @Override
  public boolean equals(Object toCompare) {
    // Compare pointers
    if (toCompare == this) {
      return true;
    }

    // Compare types
    if (!(toCompare instanceof Version)) {
      return false;
    }

    return compareTo((Version) toCompare) == 0;
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

  @Override
  public String toString() {
    return toString(this.numberOfComponents);
  }

  /**
   * Gets the version as a string using the specified number of components.
   *
   * @param components The number of components. Values less than 1 will be treated as 1 and values
   *     greater than 4 will be treated as 4.
   * @return The version as a string using the specified number of components.
   */
  public String toString(int components) {
    StringBuilder buff = new StringBuilder();
    buff.append(this.major);
    if (components >= 2) buff.append(".").append(getMinor());
    if (components >= 3) buff.append(".").append(getBuild());
    if (components >= 4) buff.append(".").append(getRevision());

    return buff.toString();
  }

  @Override
  public int compareTo(Version toCompare) {
    int result = toString().compareTo(toCompare.toString());
    if (result == 0) return result;

    result = Integer.compare(getMajorAsInt(), toCompare.getMajorAsInt());
    if (result != 0) return result;

    result = Integer.compare(getMinorAsInt(), toCompare.getMinorAsInt());
    if (result != 0) return result;

    result = Integer.compare(getBuildAsInt(), toCompare.getBuildAsInt());
    if (result != 0) return result;

    result = Integer.compare(getRevisionAsInt(), toCompare.getRevisionAsInt());
    if (result != 0) return result;

    return result;
  }

  public Pattern getPattern() {
    var builder = new StringBuilder();
    builder.append(this.major).append("[.-]").append(this.minor);
    if (this.build != null) {
      if (this.build.equals("0")) builder.append("(");
      builder.append("[.-]").append(this.build);
      if (this.build.equals("0")) builder.append(")*");
    }
    if (this.revision != null) {
      if (this.revision.equals("0")) builder.append("(");
      builder.append("[.-]").append(this.revision);
      if (this.revision.equals("0")) builder.append(")*");
    }
    return Pattern.compile(builder.toString());
  }
}
