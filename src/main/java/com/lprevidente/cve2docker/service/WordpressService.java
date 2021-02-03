package com.lprevidente.cve2docker.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.tmatesoft.svn.core.SVNDepth;
import org.tmatesoft.svn.core.SVNException;
import org.tmatesoft.svn.core.SVNURL;
import org.tmatesoft.svn.core.auth.ISVNAuthenticationManager;
import org.tmatesoft.svn.core.internal.util.SVNEncodingUtil;
import org.tmatesoft.svn.core.io.SVNRepository;
import org.tmatesoft.svn.core.io.SVNRepositoryFactory;
import org.tmatesoft.svn.core.wc.ISVNOptions;
import org.tmatesoft.svn.core.wc.SVNClientManager;
import org.tmatesoft.svn.core.wc.SVNRevision;
import org.tmatesoft.svn.core.wc.SVNWCUtil;

import java.io.File;

@Service
@Slf4j
public class WordpressService {

  public SVNClientManager getSVNClientManager() throws SVNException {
    ISVNOptions myOptions = SVNWCUtil.createDefaultOptions(true);
    ISVNAuthenticationManager myAuthManager = SVNWCUtil.createDefaultAuthenticationManager();
    return SVNClientManager.newInstance(myOptions, myAuthManager);
  }

  public boolean checkoutPlugin(String pluginName, String version, File destDir) {
    try {
      log.debug(
          "[checkoutPlugin] Request checkout - pluginName = {}  version = {}", pluginName, version);
      final var updateClient = getSVNClientManager().getUpdateClient();
      updateClient.doCheckout(
          SVNURL.parseURIEncoded(
              "https://plugins.svn.wordpress.org/" + pluginName + "/tags/" + version),
          destDir,
          SVNRevision.HEAD,
          SVNRevision.HEAD,
          SVNDepth.INFINITY,
          true);
      return true;
    } catch (SVNException e) {
      log.warn("[checkoutPlugin] Unable to checkout: " + e.getMessage());
      return false;
    }
  }

  public boolean checkoutTheme(String themeName, String version, File destDir) {
    try {
      log.debug(
          "[checkoutTheme] Request checkout - pluginName = {}  version = {}", themeName, version);
      final var updateClient = getSVNClientManager().getUpdateClient();
      updateClient.doCheckout(
          SVNURL.parseURIEncoded("https://themes.svn.wordpress.org/" + themeName + "/" + version),
          destDir,
          SVNRevision.HEAD,
          SVNRevision.HEAD,
          SVNDepth.INFINITY,
          true);
      return true;
    } catch (SVNException e) {
      log.warn("[checkoutTheme] Unable to checkout: " + e.getMessage());
      return false;
    }
  }
}
