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


def is_win_administrator() -> bool:
    if not OSType.is_win():
        return False
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        return False
