import platform

class OSType:
    @staticmethod
    def is_win() -> bool:
        return platform.system() == 'Windows'

    @staticmethod
    def is_unix() -> bool:
        return platform.system() in ['Linux', 'Darwin']

    @staticmethod
    def is_linux() -> bool:
        return platform.system() == 'Linux'

    @staticmethod
    def is_macos() -> bool:
        return platform.system() == 'Darwin'
