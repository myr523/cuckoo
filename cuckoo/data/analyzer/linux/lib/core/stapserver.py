import threading
import socket
import logging
import os

log = logging.getLogger(__name__)


class STAPDispatcher(threading.Thread):
    def __init__(self, pipe_handle, dispatcher):
        threading.Thread.__init__(self)
        self.pipe_handle = pipe_handle
        self.dispatcher = dispatcher
        self.do_run = True

    def _read_message(self):
        """Reads a message."""
        while True:
            conn, _ = self.pipe_handle.accept()
            while True:
                message = conn.recv(1024)
                return conn, message.decode()

    def run(self):
        """Run the STAP dispatcher."""
        while self.do_run:
            conn, message = self._read_message()
            if not message:
                break

            response = self.dispatcher.dispatch(message) or "OK"
            conn.send(response.encode())
            conn.close()

    def stop(self):
        self.do_run = False

class STAPServer(threading.Thread):
    def __init__(self, stap_handler, sock_name, **kwargs):
        threading.Thread.__init__(self)
        self.stap_handler = stap_handler
        self.sock_name = sock_name
        self.kwargs = kwargs
        self.do_run = True
        self.handlers = set()

    def run(self):
        sock_handle = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            os.unlink(self.sock_name)
        except FileNotFoundError:
            pass
        try:
            sock_handle.bind((self.sock_name))
        except Exception as e:
            print(e)

        sock_handle.listen(128)
        handler = self.stap_handler(sock_handle, **self.kwargs)
        handler.daemon = True
        handler.start()
        self.handlers.add(handler)

    def stop(self):
        self.do_run = False
        for h in self.handlers:
            try:
                if h.isAlive():
                    h.stop()
            except:
                pass

    # def disconnect_pipes():
    #     for sock in open_handles:
    #         try:
    #             sock.shutdown(socket.SHUT_RDWR)
    #             sock.close()
    #         except:
    #             log.exception("Could not close socket")
