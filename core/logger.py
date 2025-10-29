import atexit
from colorama import Fore, Style, init

init(autoreset=True)

class Logger:
    CLEAR_LINE = "\x1b[K"

    INFO_SYMBOL_PLAIN     = "[i]"
    WARN_SYMBOL_PLAIN     = "[W]"
    ERROR_SYMBOL_PLAIN    = "[!]"
    INFO_SYMBOL_COLOR     = f"{Fore.GREEN}{INFO_SYMBOL_PLAIN}{Style.RESET_ALL}"
    WARN_SYMBOL_COLOR     = f"{Fore.YELLOW}{WARN_SYMBOL_PLAIN}{Style.RESET_ALL}"
    ERROR_SYMBOL_COLOR    = f"{Fore.RED}{ERROR_SYMBOL_PLAIN}{Style.RESET_ALL}"
    
    FINDING_BANNER_PLAIN  = "=" * 50
    FINDING_BANNER_COLOR  = f"{Fore.YELLOW}{FINDING_BANNER_PLAIN}{Style.RESET_ALL}"

    def __init__(self, log_filename=None, quiet=False):
        self.quiet = quiet
        self.log_file = None

        # if the user specified an output file, add a file handler
        if log_filename:
            try:
                self.log_file = open(log_filename, "w")
            except OSError as e:
                print(f"Unexpected error: {e.__class__.__name__}")
                exit()
        
            # close the log file when the program exits
            atexit.register(self._close_log_file)

    def _close_log_file(self):
        if self.log_file: self.log_file.close()

    def _console_log(self, message, overwritable=False):
        line_end = "\r" if overwritable else "\n"
        print(f"{self.CLEAR_LINE}{message}", flush=True, end=line_end)

    def _file_log(self, message):
        if not self.log_file: return
        self.log_file.write(f"{message}\n")
        self.log_file.flush()

    def _beautify_finding(self, finding, color=False):
        pretty  = self.FINDING_BANNER_COLOR if color else self.FINDING_BANNER_PLAIN
        pretty += "\n"
        pretty += f"Finding: {finding.title} on {finding.host}\n\n"
        pretty += "This payload caused a timeout:\n\n"
        
        pretty += f"{Fore.CYAN}" if color else ""
        for line in finding.req.splitlines(keepends=True):
            pretty += line.encode("unicode_escape").decode("utf-8") + "\n"
        pretty += f"{Style.RESET_ALL}" if color else ""
        pretty += "\n"

        if finding.gadget_required:
            pretty += "Note: An early-response gadget is required to exploit this vulnerability!\n\n"

        pretty += self.FINDING_BANNER_COLOR if color else self.FINDING_BANNER_PLAIN

        return pretty

    def info(self, message, overwritable=False):
        if self.quiet: return
        self._console_log(f"{self.INFO_SYMBOL_COLOR} {message}", overwritable=overwritable)
    
    def warning(self, message, overwritable=False):
        if self.quiet: return
        self._console_log(f"{self.WARN_SYMBOL_COLOR} {message}", overwritable=overwritable)

    def error(self, message, overwritable=False):
        if self.quiet: return
        self._console_log(f"{self.ERROR_SYMBOL_COLOR} {message}", overwritable=overwritable)

    def finding(self, finding):
        # log to console
        self._console_log(self._beautify_finding(finding, color=True))

        # if the user specified an output file, log to file as well
        if not self.log_file: return
        self._file_log(self._beautify_finding(finding, color=False))

