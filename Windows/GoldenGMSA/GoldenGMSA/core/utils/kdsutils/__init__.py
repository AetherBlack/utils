
import time

class KDSUtils:

    KeyCycleDuration = 360000000000
    EPOCH_DIFF = 11644473600

    @staticmethod
    def getCurrentIntervalID(keyCycleDuration: int, someFlag: int) -> int:
        currentTime = KDSUtils.dateTimeNowToFileTimeUtc()
    
        if someFlag != 0:
            currentTime += 3000000000

        temp = currentTime // keyCycleDuration

        l0KeyID = temp // 1024
        l1KeyID = (temp // 32) & 31
        l2KeyID = temp & 31

        return l0KeyID, l1KeyID, l2KeyID

    @staticmethod
    def dateTimeNowToFileTimeUtc() -> int:
        """
        DateTime.Now.ToFileTimeUtc Windows like.
        """
        # Thanks to: https://stackoverflow.com/questions/3585583/convert-unix-linux-time-to-windows-filetime
        tv_sec, tv_usec = str(time.time()).split(".")
        return ((KDSUtils.EPOCH_DIFF + tv_sec) * 10000000) + (tv_usec * 10)
