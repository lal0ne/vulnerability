#
# colors.py
#
# Color Code Functions in Python
# Works on Winblows or *nix
#
# By: torBot
#
# Use it like a module & import the available functions, then call as you like:
#    from colors import *
#    status("This is a status message")
#    pad(); print red("This is red text")
#    pad(); print blue("This is blue text\n")
#    caution("Cautionary Message")
#    pad()
#    error("This is an error message\n\n")
#

import os, sys
from ctypes import Structure, c_short, c_ushort, byref

if os.name == 'nt' or sys.platform.startswith('win'):
  from ctypes import windll, Structure, c_short, c_ushort, byref

# Winblows Constants
################################
SHORT = c_short
WORD = c_ushort

# winbase.h
STD_INPUT_HANDLE  = -10
STD_OUTPUT_HANDLE = -11
STD_ERROR_HANDLE  = -12

# wincon.h structs
class COORD(Structure):
  _fields_ = [ ("X", SHORT), ("Y", SHORT)]

class SMALL_RECT(Structure):
  _fields_ = [("Left", SHORT), ("Top", SHORT),
    ("Right", SHORT), ("Bottom", SHORT)]

class CONSOLE_SCREEN_BUFFER_INFO(Structure):
  _fields_ = [
    ("dwSize", COORD), ("dwCursorPosition", COORD),
    ("wAttributes", WORD), ("srWindow", SMALL_RECT),
    ("dwMaximumWindowSize", COORD)]


# OS Color Definitions & Setup
################################
if os.name == 'nt' or sys.platform.startswith('win'):
  stdout_handle = windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
  SetConsoleTextAttribute = windll.kernel32.SetConsoleTextAttribute
  GetConsoleScreenBufferInfo = windll.kernel32.GetConsoleScreenBufferInfo

  # wincon.h
  DIM  = 0x00   # dim
  RS   = ""     # reset (?)
  HC   = 0x08   # hicolor
  BHC  = 0x80   # background hicolor
  UL   = ""     # underline (no workie on winblows)
  INV  = ""     # inverse background and foreground (no workie on winblows)
  FBLK = 0x0000 # foreground black
  FBLK = 0x0008 # foreground grey
  FRED = 0x0004 # foreground red
  FGRN = 0x0002 # foreground green
  FYEL = 0x0006 # foreground yellow
  FBLU = 0x0001 # foreground blue
  FMAG = 0x0005 # foreground magenta
  FCYN = 0x0003 # foreground cyan
  FWHT = 0x0007 # foreground white (grey)
  BBLK = 0x0000 # background black
  BBLK = 0x0080 # background grey
  BRED = 0x0040 # background red
  BGRN = 0x0020 # background green
  BYEL = 0x0060 # background yellow
  BBLU = 0x0010 # background blue
  BMAG = 0x0050 # background magenta
  BCYN = 0x0030 # background cyan
  BWHT = 0x0070 # background white (grey)
else:
  # ANSI color code escapes, for *nix
  DIM  = ""       # dim (no workie)
  RS="\033[0m"    # reset
  HC="\033[1m"    # hicolor
  UL="\033[4m"    # underline
  INV="\033[7m"   # inverse background and foreground
  FBLK="\033[30m" # foreground black
  FRED="\033[31m" # foreground red
  FGRN="\033[32m" # foreground green
  FYEL="\033[33m" # foreground yellow
  FBLU="\033[34m" # foreground blue
  FMAG="\033[35m" # foreground magenta
  FCYN="\033[36m" # foreground cyan
  FWHT="\033[37m" # foreground white
  BBLK="\033[40m" # background black
  BRED="\033[41m" # background red
  BGRN="\033[42m" # background green
  BYEL="\033[43m" # background yellow
  BBLU="\033[44m" # background blue
  BMAG="\033[45m" # background magenta
  BCYN="\033[46m" # background cyan
  BWHT="\033[47m" # background white

def get_text_attr():
  """
      Returns the character attributes (colors) of the console screen buffer.

      Used for windows only
  """
  if os.name == 'nt' or sys.platform.startswith('win'):
    try:
      csbi = CONSOLE_SCREEN_BUFFER_INFO()
      GetConsoleScreenBufferInfo(stdout_handle, byref(csbi))
      return csbi.wAttributes
    except Exception, e:
      pass
  return None


def set_text_attr(color):
  """
      Sets the character attributes (colors) of the console screen
      buffer. Color is a combination of foreground and background color,
      foreground and background intensity.

      Used for windows only
  """
  if os.name == 'nt' or sys.platform.startswith('win'):
    try:
      SetConsoleTextAttribute(stdout_handle, color)
      return True
    except Exception, e:
      pass
  return False


def windows_default_colors():
  """
      Checks and returns the current windows console color mapping
      Returns the necessary foreground and background code to reset later

      Used for windows only
  """
  if os.name == 'nt' or sys.platform.startswith('win'):
    try:
      default_colors = get_text_attr()
      default_bg = default_colors & 0x0070
      return default_bg
    except Exception, e:
      pass
  return None


def restore_windows_colors(default_gb):
  """
      Set or Restore the console colors to the provided foreground + background codes
      Returns True or False

      Used for windows only
  """
  if os.name == 'nt' or sys.platform.startswith('win'):
    try:
      set_text_attr(default_gb)
      return True
    except Exception, e:
      pass
  return False


# Some Simple Print functions
#############################
def pad(): 
  """ Simple pad to make sub points easier to print """
  sys.stdout.write('   ')

def caution(msg): 
  """ [*] Print a cautionary message to user """
  if os.name == 'nt' or sys.platform.startswith('win'):
    windows_user_default_color_code = windows_default_colors()
    set_text_attr(FYEL | BBLK | HC | BHC)
    sys.stdout.write("[")
    set_text_attr(FWHT | BBLK | HC | BHC)
    sys.stdout.write("*")
    set_text_attr(FYEL | BBLK | HC | BHC)
    sys.stdout.write("] ")
    set_text_attr(FWHT | BBLK | HC | BHC)
    sys.stdout.write(str(msg) + "\n")
    restore_windows_colors(windows_user_default_color_code)
  else:
    print HC + FYEL + "[" + FWHT + "-" + FYEL + "] " + FWHT + str( msg ) + RS


def good( msg ): 
  """ [*] Print a success message to user """
  if os.name == 'nt' or sys.platform.startswith('win'):
    windows_user_default_color_code = windows_default_colors()
    set_text_attr(FGRN | BBLK | HC | BHC)
    sys.stdout.write("[")
    set_text_attr(FWHT | BBLK | HC | BHC)
    sys.stdout.write("*")
    set_text_attr(FGRN | BBLK | HC | BHC)
    sys.stdout.write("] ")
    set_text_attr(FWHT | BBLK | HC | BHC)
    sys.stdout.write(str(msg) + "\n")
    restore_windows_colors(windows_user_default_color_code)
  else:
    print HC + FGRN + "[" + FWHT + "*" + FGRN + "] " + FWHT + str( msg ) + RS


def bad( msg ): 
  """ [x] Print a warning or bad message to user """
  if os.name == 'nt' or sys.platform.startswith('win'):
    windows_user_default_color_code = windows_default_colors()
    set_text_attr(FRED | BBLK | HC | BHC)
    sys.stdout.write("[")
    set_text_attr(FWHT | BBLK | HC | BHC)
    sys.stdout.write("x")
    set_text_attr(FRED | BBLK | HC | BHC)
    sys.stdout.write("] ")
    set_text_attr(FWHT | BBLK | HC | BHC)
    sys.stdout.write(str(msg) + "\n")
    restore_windows_colors(windows_user_default_color_code)
  else:
    print HC + FRED + "[" + FWHT + "x" + FRED + "] " + FWHT + str( msg ) + RS


def status(msg ): 
  """ [*] Print a status message to user """
  if os.name == 'nt' or sys.platform.startswith('win'):
    windows_user_default_color_code = windows_default_colors()
    set_text_attr(FBLU | BBLK | HC | BHC)
    sys.stdout.write("[")
    set_text_attr(FWHT | BBLK | HC | BHC)
    sys.stdout.write("*")
    set_text_attr(FBLU | BBLK | HC | BHC)
    sys.stdout.write("] ")
    set_text_attr(FWHT | BBLK | HC | BHC)
    sys.stdout.write(str(msg) + "\n")
    restore_windows_colors(windows_user_default_color_code)
  else:
    print HC + FBLU + "[" + FWHT + "*" + FBLU + "] " + FWHT + str( msg ) + RS


def error( msg ): 
  """ [ERROR] Print an ERROR message to user """
  if os.name == 'nt' or sys.platform.startswith('win'):
    windows_user_default_color_code = windows_default_colors()
    set_text_attr(FRED | BBLK | HC | BHC)
    sys.stdout.write("[")
    set_text_attr(FWHT | BBLK | HC | BHC)
    sys.stdout.write("ERROR")
    set_text_attr(FRED | BBLK | HC | BHC)
    sys.stdout.write("] ")
    set_text_attr(FWHT | BBLK | HC | BHC)
    sys.stdout.write(str(msg) + "\n")
    restore_windows_colors(windows_user_default_color_code)
  else:
    print HC + FRED + "[" + FWHT + "ERROR" + FRED + "] " + FWHT + str( msg ) + RS


def underline( msg ): 
  """ Underline message string (no workie on windows) """
  if os.name == 'nt' or sys.platform.startswith('win'):
    return str(msg)
  return UL + str(msg) + RS


# General Colorize Text Wrappers
################################
def blue( msg ): 
  """ Print BLUE Colored String """
  if os.name == 'nt' or sys.platform.startswith('win'):
    windows_user_default_color_code = windows_default_colors()
    set_text_attr(FBLU | BBLK | HC | BHC)
    sys.stdout.write(str(msg))
    restore_windows_colors(windows_user_default_color_code)
  else:
    return HC + FBLU + str(msg) + RS


def cyan( msg ): 
  """ Print CYAN Colored String """
  if os.name == 'nt' or sys.platform.startswith('win'):
    windows_user_default_color_code = windows_default_colors()
    set_text_attr(FCYN | BBLK | HC | BHC)
    sys.stdout.write(str(msg))
    restore_windows_colors(windows_user_default_color_code)
  else:
    return HC + FCYN + str(msg) + RS


def green( msg ): 
  """ Print GREEN Colored String """
  if os.name == 'nt' or sys.platform.startswith('win'):
    windows_user_default_color_code = windows_default_colors()
    set_text_attr(FGRN | BBLK | HC | BHC)
    sys.stdout.write(str(msg))
    restore_windows_colors(windows_user_default_color_code)
  else:
    return HC + FGRN + str(msg) + RS

def magenta(msg): 
  """ Print MAGENTA Colored String """
  if os.name == 'nt' or sys.platform.startswith('win'):
    windows_user_default_color_code = windows_default_colors()
    set_text_attr(FMAG | BBLK | HC | BHC)
    sys.stdout.write(str(msg))
    restore_windows_colors(windows_user_default_color_code)
  else:
    return HC + FMAG + str(msg) + RS


def red( msg ): 
  """ Print RED Colored String """
  if os.name == 'nt' or sys.platform.startswith('win'):
    windows_user_default_color_code = windows_default_colors()
    set_text_attr(FRED | BBLK | HC | BHC)
    sys.stdout.write(str(msg))
    restore_windows_colors(windows_user_default_color_code)
  else:
    return HC + FRED + str(msg) + RS


def white( msg ): 
  """ Print WHITE Colored String """
  if os.name == 'nt' or sys.platform.startswith('win'):
    windows_user_default_color_code = windows_default_colors()
    set_text_attr(FWHT | BBLK | HC | BHC)
    sys.stdout.write(str(msg))
    restore_windows_colors(windows_user_default_color_code)
  else:
    return HC + FWHT + str(msg) + RS


def yellow(msg ): 
  """ Print YELLOW Colored String """
  if os.name == 'nt' or sys.platform.startswith('win'):
    windows_user_default_color_code = windows_default_colors()
    set_text_attr(FYEL | BBLK | HC | BHC)
    sys.stdout.write(str(msg))
    restore_windows_colors(windows_user_default_color_code)
  else:
    return HC + FYEL + str(msg) + RS

