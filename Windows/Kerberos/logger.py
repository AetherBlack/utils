
from colorama import Fore, Style

import sys


class Logger:

    @staticmethod
    def to_stdout(string: str, end: str = "\n") -> None:
        """
        Write the `string` to the stdout.
        @param: `string`(`str`) : String to write to the STDOUT.
        @param: `end`(`str`) : End of the string.
        """
        sys.stdout.write(f"{string}{end}")
        sys.stdout.flush()
    
    @staticmethod
    def error(string: str, end: str = "\n") -> None:
        """
        Write a red `string` to the stdout.
        @param: `string`(`str`) : String to write to the STDOUT.
        @param: `end`(`str`) : End of the string.
        """
        Logger.to_stdout(f"{Fore.RED}[❌] {string}{Style.RESET_ALL}", end)
    
    @staticmethod
    def information(string: str, end: str = "\n") -> None:
        """
        Write a informations message to the stdout.
        @param: `string`(`str`) : String to write to the STDOUT.
        @param: `end`(`str`) : End of the string.
        """
        Logger.to_stdout(f"{Fore.BLUE}[i]{Style.RESET_ALL} {string}", end)
    
    @staticmethod
    def ok(string: str, end: str = "\n") -> None:
        """
        Write a green `string` to the stdout.
        @param: `string`(`str`) : String to write to the STDOUT.
        @param: `end`(`str`) : End of the string.
        """
        Logger.to_stdout(f"{Fore.GREEN}[✔️] {string}{Style.RESET_ALL}", end)
    
    @staticmethod
    def warning(string: str, end: str = "\n") -> None:
        """
        Write a yellow `string` to the stdout.
        @param: `string`(`str`) : String to write to the STDOUT.
        @param: `end`(`str`) : End of the string.
        """
        Logger.to_stdout(f"{Fore.YELLOW}[⚠️] {string}{Style.RESET_ALL}", end)
