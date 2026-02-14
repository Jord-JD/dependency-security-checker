<?php

use JordJD\CliProgressBar\ProgressBar;
use JordJD\DOFileCache\DOFileCache;

$vendorDirectory = realpath(__DIR__.'/../../../../vendor');
if (!file_exists($vendorDirectory) || !is_dir($vendorDirectory)) {
    $vendorDirectory = realpath(__DIR__.'/../vendor');
    if (!file_exists($vendorDirectory) || !is_dir($vendorDirectory)) {
        die('Error locating vendor directory.');
    }
}

require_once $vendorDirectory.'/autoload.php';

$apiKey = getenv('VIRUSTOTAL_API_KEY');

if (!$apiKey) {
    die('No Virus Total API key specified. Please specify one with `export VIRUSTOTAL_API_KEY=abc123`.'.PHP_EOL);
}

$cacheDirectory = $_SERVER['HOME'].'/.cache/dependency-security-checker/';

$vtFile = new VirusTotal\File($apiKey);

if (!file_exists($cacheDirectory)) {
    $directoryMade = mkdir($cacheDirectory, 0777, true);
    if (!$directoryMade) {
        die('Unable to create cache directory at: '.$cacheDirectory.PHP_EOL);
    }
}

$cache = new DOFileCache();
$cache->changeConfig(['cacheDirectory' => $cacheDirectory]);

$packages = array_values(array_filter(glob($vendorDirectory.'/*/*'), function ($package) {
    return is_dir($package);
}));

$progressBar = new ProgressBar();
$progressBar->setMaxProgress(count($packages));

$progressBar->display();

$results = [
    'safe' => [],
    'unsafe' => [],
    'unknown' => [],
];

foreach ($packages as $package) {
    $packageName = str_replace($vendorDirectory.'/', '', $package);

    $progressBar->setMessage($packageName)->display();

    $result = packageScan($package);
    $status = $result['status'];
    $url = $result['url'];

    $results[$status][] = [
        'package_name' => $packageName,
        'url' => $url,
    ];

    $progressBar->advance()->display();
}

$progressBar->complete();

echo 'Results: '.PHP_EOL;
echo '* '.count($packages)." packages scanned.".PHP_EOL;

if ($results['safe']) {
    echo '* ' . count($results['safe']) . ' packages are safe.' . PHP_EOL;
}

if ($results['unknown']) {
    echo '* ' . count($results['unknown']) . ' packages still being scanned. Try again in a few minutes.' . PHP_EOL;
}

if ($results['unsafe']) {
    echo '* ' . count($results['unsafe']) . ' packages may be UNSAFE!' . PHP_EOL;

    foreach ($results['unsafe'] as $unsafePackages) {
        echo ' * UNSAFE: ' . $unsafePackages['package_name'] . ' - '.$unsafePackages['url']. PHP_EOL;
    }
}

function packageScan($package)
{
    global $vtFile, $cache;

    $packageZipFile = sys_get_temp_dir().'/'.sha1($package);

    // Initialize archive object
    $zip = new ZipArchive();
    $zip->open($packageZipFile, ZipArchive::CREATE | ZipArchive::OVERWRITE );

    // Create recursive directory iterator
    /** @var SplFileInfo[] $files */
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($package), RecursiveIteratorIterator::LEAVES_ONLY);

    foreach ($files as $name => $file)
    {
        // Skip directories (they would be added automatically)
        if (!$file->isDir())
        {
            // Get real and relative path for current file
            $filePath = $file->getRealPath();
            $relativePath = substr($filePath, strlen($package) + 1);

            // Add current file to archive
            $zip->addFile($filePath, $relativePath);
        }
    }

    // Zip archive will be created only after closing object
    $zip->close();

    $hash = hash_file('sha256', $packageZipFile);

    $response = $cache->get($hash);

    if (!$response) {

        sleep(15);
        $response = $vtFile->getReport($hash);

        $cache->set($hash, $response);

    }

    if (!isset($response['scans']) || !$response['scans']) {
        
        $status = 'unknown';

        $url = fileSubmit($packageZipFile);
        
    } else {

        $status = 'safe';

        foreach($response['scans'] as $scan) {
            if ($scan['result']) {
                $status = 'unsafe';
                break;
            }
        }

        $url = $response['permalink'];

    }

    if ($status!='safe') {
        $cache->delete($hash);
    }

    unlink($packageZipFile);

    return [
        'status' => $status,
        'url' => $url,
    ];
}

function fileSubmit($file)
{
    global $vtFile;

    sleep(15);
    $response = $vtFile->scan($file);

    if (isset($response['permalink']) && $response['permalink']) {
        return $response['permalink'];
    }

    return false;
}


