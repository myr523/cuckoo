import threading
import logging

log = logging.getLogger(__name__)


class STAPDispatcher(threading.Thread):
    def __init__(self, message, dispatcher):
        threading.Thread.__init__(self)
        self.message = message
        self.dispatcher = dispatcher
        self.do_run = True

    def run(self):
        """Run the STAP dispatcher."""
        log.info("dispather: " + self.message)
        self.dispatcher.dispatch(self.message)

    def stop(self):
        self.do_run = False

class STAPServer(threading.Thread):
    def __init__(self, reader, file_handle, **kwargs):
        threading.Thread.__init__(self)
        self.reader = reader
        self.file_handle = file_handle
        self.kwargs = kwargs
        self.do_run = True
        self.handlers = set()

    def run(self):
        log.info("start STAPServer")
        while True:
            line = self.file_handle.readline()
            if not line:
                log.debug("readline error")
                continue
            handler = self.reader(line, **self.kwargs)
            handler.daemon = True
            handler.start()
            self.handlers.add(handler)

    def stop(self):
        log.info("stopping STAP module...")
        try:
            if not self.file_handle.closed:
                log.info(self.file_handle.closed)
                self.file_handle.close()
        except Exception as e:
            log.error(e)

        self.do_run = False
        for h in self.handlers:
            try:
                if h.isAlive():
                    h.stop()
            except:
                pass