<?php
/**
 * Command-line extension installer. This file is meant to be copied into your Joomla! 3 site's cli directory.
 * Thanks Nic Dionysopoulos and Akeeba for this file!
 */

// Define ourselves as a parent file
define('_JEXEC', 1);

// Required by the CMS
define('DS', DIRECTORY_SEPARATOR);

// Timezone fix; avoids errors printed out by PHP 5.3.3+ (thanks Yannick!)
if (function_exists('date_default_timezone_get') && function_exists('date_default_timezone_set'))
{
    if (function_exists('error_reporting'))
    {
        $oldLevel = error_reporting(0);
    }
    $serverTimezone = @date_default_timezone_get();
    if (empty($serverTimezone) || !is_string($serverTimezone))
    {
        $serverTimezone = 'UTC';
    }
    if (function_exists('error_reporting'))
    {
        error_reporting($oldLevel);
    }
    @date_default_timezone_set($serverTimezone);
}

// Load system defines
if (file_exists(__DIR__ . '/defines.php'))
{
    include_once __DIR__ . '/defines.php';
}

if (!defined('_JDEFINES'))
{
    $path = rtrim(__DIR__, DIRECTORY_SEPARATOR);
    $rpos = strrpos($path, DIRECTORY_SEPARATOR);
    $path = substr($path, 0, $rpos);
    define('JPATH_BASE', $path);
    require_once JPATH_BASE . '/includes/defines.php';
}

// Load the rest of the framework include files
if (file_exists(JPATH_LIBRARIES . '/import.legacy.php'))
{
    require_once JPATH_LIBRARIES . '/import.legacy.php';
}
else
{
    require_once JPATH_LIBRARIES . '/import.php';
}

require_once JPATH_LIBRARIES . '/cms.php';

// Load the JApplicationCli class
JLoader::import('joomla.application.cli');
JLoader::import('joomla.application.component.helper');
JLoader::import('cms.component.helper');

class JoomlaExtensionInstallerCli extends JApplicationCli
{
    /**
     * JApplicationCli didn't want to run on PHP CGI. I have my way of becoming
     * VERY convincing. Now obey your true master, you petty class!
     *
     * @param JInputCli   $input
     * @param JRegistry   $config
     * @param JDispatcher $dispatcher
     */
    public function __construct(JInputCli $input = null, JRegistry $config = null, JDispatcher $dispatcher = null)
    {
        // Close the application if we are not executed from the command line, Akeeba style (allow for PHP CGI)
        if (array_key_exists('REQUEST_METHOD', $_SERVER))
        {
            die('You are not supposed to access this script from the web. You have to run it from the command line. If you don\'t understand what this means, you must not try to use this file before reading the documentation. Thank you.');
        }

        $cgiMode = false;

        if (!defined('STDOUT') || !defined('STDIN') || !isset($_SERVER['argv']))
        {
            $cgiMode = true;
        }

        // If a input object is given use it.
        if ($input instanceof JInput)
        {
            $this->input = $input;
        }
        // Create the input based on the application logic.
        else
        {
            if (class_exists('JInput'))
            {
                if ($cgiMode)
                {
                    $query = "";
                    if (!empty($_GET))
                    {
                        foreach ($_GET as $k => $v)
                        {
                            $query .= " $k";
                            if ($v != "")
                            {
                                $query .= "=$v";
                            }
                        }
                    }
                    $query = ltrim($query);
                    $argv  = explode(' ', $query);
                    $argc  = count($argv);

                    $_SERVER['argv'] = $argv;
                }

                $this->input = new JInputCLI();
            }
        }

        // If a config object is given use it.
        if ($config instanceof JRegistry)
        {
            $this->config = $config;
        }
        // Instantiate a new configuration object.
        else
        {
            $this->config = new JRegistry;
        }

        // If a dispatcher object is given use it.
        if ($dispatcher instanceof JDispatcher)
        {
            $this->dispatcher = $dispatcher;
        }
        // Create the dispatcher based on the application logic.
        else
        {
            $this->loadDispatcher();
        }

        // Load the configuration object.
        $this->loadConfiguration($this->fetchConfigurationData());

        // Set the execution datetime and timestamp;
        $this->set('execution.datetime', gmdate('Y-m-d H:i:s'));
        $this->set('execution.timestamp', time());

        // Set the current directory.
        $this->set('cwd', getcwd());
    }

    public function flushAssets()
    {
        // This is an empty function since JInstall will try to flush the assets even if we're in CLI (!!!)
        return true;
    }

    public function execute()
    {
        JLoader::import('joomla.application.component.helper');
        JLoader::import('joomla.updater.update');
        JLoader::import('joomla.filesystem.file');
        JLoader::import('joomla.filesystem.folder');

        // Load the language files
        $paths = [JPATH_ADMINISTRATOR, JPATH_ROOT];
        $jlang = JFactory::getLanguage();
        $jlang->load('lib_joomla', $paths[0], 'en-GB', true);

        $packageFile = $this->input->get('package', null, 'folder');

        if (!JFile::exists($packageFile))
        {
            $this->out("Package file $packageFile does not exist");
            $this->close(1);
        }

        // Attempt to use an infinite time limit, in case you are using the PHP CGI binary instead
        // of the PHP CLI binary. This will not work with Safe Mode, though.
        $safe_mode = true;

        if (function_exists('ini_get'))
        {
            $safe_mode = ini_get('safe_mode');
        }

        if (!$safe_mode && function_exists('set_time_limit'))
        {
            @set_time_limit(0);
        }

        // Unpack the downloaded package file
        $package = JInstallerHelper::unpack($packageFile);

        if (!$package)
        {
            $this->out("An error occurred while unpacking the file");
            $this->close(3);
        }

        $installer = new JInstaller;
        $installed = $installer->install($package['extractdir']);

        // Let's cleanup the downloaded archive and the temp folder
        if (JFolder::exists($package['extractdir']))
        {
            JFolder::delete($package['extractdir']);
        }

        if (JFile::exists($package['packagefile']))
        {
            JFile::delete($package['packagefile']);
        }

        if ($installed)
        {
            $this->out("Extension successfully installed");
            $this->close(0);
        }
        else
        {
            $this->out("Extension installation failed");
            $this->close(250);
        }
    }

    public function getTemplate($params = false)
    {
        return '';
    }

    public function setHeader($name, $value, $replace = false)
    {
        return $this;
    }

    public function getCfg($name, $default = null)
    {
        return $this->get($name, $default);
    }

    public function getClientId()
    {
        return 1;
    }

    public function isClient($identifier)
    {
        return $identifier === 'administrator';
    }

    public function setUserState($key, $value)
    {
        $session  = &JFactory::getSession();
        $registry = &$session->get('registry');

        if (!is_null($registry))
        {
            return $registry->setValue($key, $value);
        }

        return null;
    }

    /**
     * Some packages call allowCache as part of pre-/post-installation script to determine if request caching is
     * allowed. Since we're in a CLI app this does not apply and we need to always return false.
     *
     * @param boolean $allow
     *
     * @return bool
     */
    public function allowCache($allow = null)
    {
        return false;
    }

    /**
     * By convention, most installation packages will display detailed HTML messages. We will capture said messages,
     * strip all tags and dump the plain text representation to the standard output.
     *
     * @param string $msg
     * @param string $type
     *
     * @return void
     */
    public function enqueueMessage($msg, $type = 'message')
    {
        $this->out(strip_tags($msg));
    }

    /**
     * Certain extensions will attempt to perform a redirect, usually to their own component. Since we're in a CLI
     * application this won't work. We will only output the redirection URL.
     *
     * Extension developers: be aware that this is arguably an anti-pattern. If you want to perform an operation which
     * might take a long time you can always use a hidden option in your config.xml to indicate whether said operation
     * has been carried out. If not, the first time your user visits your extension you can tell them that housekeeping
     * needs to run and do your fancy AJAX-powered tasks then. Do NOT do redirects at the end of your post-installation
     * script. You are not cowboys and this ain't the Wild West, partner!
     *
     * @param string $url
     * @param int    $status
     *
     * @return void
     */
    public function redirect($url, $status = 303)
    {
        $status = (int) $status;
        $status = empty($status) ? 303 : $status;

        $this->out("Redirect with HTTP $status attempted to $url");

        return;
    }
}

$app                   = JApplicationCli::getInstance('JoomlaExtensionInstallerCli');
JFactory::$application = $app;
$app->execute();
