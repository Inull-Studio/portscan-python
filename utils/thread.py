from concurrent.futures import ThreadPoolExecutor
import threading

class ThreadPoolExecutor(ThreadPoolExecutor):
    def shutdown(self, wait: bool = False, *, cancel_futures: bool = True) -> None:
        super().shutdown(wait, cancel_futures=cancel_futures)