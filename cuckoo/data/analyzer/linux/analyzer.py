# Copyright (C) 2015-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import socket
import pkgutil
import logging
import tempfile
import xmlrpclib
import hashlib
import traceback
import urllib
import urllib2
import time
import datetime

from lib.api.process import Process
from lib.common.abstracts import Package, Auxiliary
from lib.common.constants import PATHS
from lib.common.exceptions import CuckooError, CuckooPackageError
from lib.common.hashing import hash_file
from lib.common.results import upload_to_host
from lib.common.uploaddropped import upload_to_host_dropped
from lib.core.config import Config
from lib.core.startup import create_folders, init_logging
from lib.core.stapserver import STAPServer, STAPDispatcher
from modules import auxiliary

log = logging.getLogger("analyzer")

PID = os.getpid()
FILES_LIST = set()
DUMPED_LIST = set()
PROCESS_LIST = set()
SEEN_LIST = set()
PPID = Process(pid=PID).get_parent_pid()
PRESERVE_SUFFIX = ".old"
STAP_PROC_PATH = ""

def add_pids(pids):
    """Add PID."""
    if not isinstance(pids, (tuple, list, set)):
        pids = [pids]

    for pid in pids:
        log.info("Added new process to list with pid: %s", pid)
        pid = int(pid)
        if pid not in SEEN_LIST:
            PROCESS_LIST.add(pid)
        SEEN_LIST.add(pid)


class Files(object):
    PROTECTED_NAMES = ()

    def __init__(self):
        self.files = {}
        self.files_orig = {}
        self.dumped = []

    def is_protected_filename(self, file_name):
        """Return whether or not to inject into a process with this name."""
        return file_name in self.PROTECTED_NAMES

    def remove_suffix(self, filepath):
        return filepath.replace(PRESERVE_SUFFIX, "")

    def add_pid(self, filepath, pid, verbose=True):
        """Track a process identifier for this file."""
        if not pid or filepath not in self.files:
            return

        if pid not in self.files[filepath]:
            self.files[filepath].append(pid)
            verbose and log.info("Added pid %s for %r", pid, filepath)

    def add_file(self, filepath, pid=None):
        """Add filepath to the list of files and track the pid."""
        if filepath not in self.files:
            log.info(
                "Added new file to list with pid %s and path %s",
                pid, filepath.encode("utf8")
            )
            self.files[filepath] = []
            self.files_orig[filepath] = filepath

        self.add_pid(filepath, pid, verbose=False)

    def dump_delete_file(self, filepath):
        """Dump a file to the host."""
        if not os.path.isfile(filepath):
            log.warning("File at path %r does not exist, skip.", filepath)
            return False

        # Check whether we've already dumped this file - in that case skip it.
        try:
            sha256 = hash_file(hashlib.sha256, filepath)
            if sha256 in self.dumped:
                return
        except IOError as e:
            log.info("Error dumping file from path \"%s\": %s", filepath, e)
            return

        filename = "%s_%s" % (sha256[:16], os.path.basename(self.remove_suffix(filepath)))
        upload_path = os.path.join("files", filename)

        try:
            upload_to_host_dropped(
                self.files_orig.get(filepath.lower(), filepath), PRESERVE_SUFFIX,
                upload_path, self.files.get(filepath, [])
            )
            self.dumped.append(sha256)
        except (IOError, socket.error) as e:
            log.error(
                "Unable to upload dropped file at path \"%s\": %s",
                filepath, e
            )

    def dump_file(self, filepath):
        """Dump a file to the host."""
        if not os.path.isfile(filepath):
            log.warning("File at path %r does not exist, skip.", filepath)
            return False

        # Check whether we've already dumped this file - in that case skip it.
        try:
            sha256 = hash_file(hashlib.sha256, filepath)
            if sha256 in self.dumped:
                return
        except IOError as e:
            log.info("Error dumping file from path \"%s\": %s", filepath, e)
            return

        filename = "%s_%s" % (sha256[:16], os.path.basename(filepath))
        upload_path = os.path.join("files", filename)

        try:
            upload_to_host(
                self.files_orig.get(filepath.lower(), filepath),
                upload_path, self.files.get(filepath, [])
            )
            self.dumped.append(sha256)
        except (IOError, socket.error) as e:
            log.error(
                "Unable to upload dropped file at path \"%s\": %s",
                filepath, e
            )


    def delete_file(self, filepath, pid=None):
        """A file is about to removed and thus should be dumped right away."""
        self.add_pid(filepath, pid)
        self.dump_delete_file(filepath)

        # Remove the filepath from the files list.
        self.files.pop(filepath, None)
        self.files_orig.pop(filepath, None)

    def move_file(self, oldfilepath, newfilepath, pid=None):
        """A file will be moved - track this change."""
        self.add_pid(oldfilepath, pid)
        if oldfilepath in self.files:
            # Replace the entry with the new filepath.
            self.files[newfilepath] = \
                self.files.pop(oldfilepath, [])

    def dump_files(self):
        """Dump all pending files."""
        while self.files:
            self.delete_file(self.files.keys()[0])


class CommandSTAPHandler():
    """STAP Handler.

    This class handles the notifications received through the STAP stdout and
    decides what to do with them.
    """
    ignore_list = dict(pid=[])

    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.tracked = {}

    def _handle_file_new(self, data):
        """Notification of a new dropped file."""
        self.analyzer.files.add_file(data.decode("utf8"), self.pid)

    def _handle_file_del(self, data):
        """Notification of a file being removed (if it exists) - we have to
        dump it before it's being removed."""
        filepath = data.decode("utf8")
        log.info("delete handler: %s", filepath)

        # TODO: skip own PID
        if os.path.exists(filepath):
            self.analyzer.files.delete_file(filepath, self.pid)
            # After preserve file, remove it
            os.remove(filepath)

    def _handle_file_move(self, data):
        """A file is being moved - track these changes."""
        if "::" not in data:
            log.warning("Received FILE_MOVE command from monitor with an "
                        "incorrect argument.")
            return

        old_filepath, new_filepath = data.split("::", 1)
        self.analyzer.files.move_file(
            old_filepath.decode("utf8"), new_filepath.decode("utf8"), self.pid
        )

    def dispatch(self, data):
        response = "NOPE"

        if not data or ":" not in data:
            log.critical("Unknown command received from the monitor: %r",
                         data.strip())
        else:
            # Backwards compatibility (old syntax is, e.g., "FILE_NEW:" vs the
            # new syntax, e.g., "1234:FILE_NEW:").
            if data[0].isupper():
                command, arguments = data.strip().split(":", 1)
                self.pid = None
            else:
                self.pid, command, arguments = data.strip().split(":", 2)

            fn = getattr(self, "_handle_%s" % command.lower(), None)
            if not fn:
                log.critical("Unknown command received from the monitor: %r",
                             data.strip())
            else:
                try:
                    response = fn(arguments)
                except:
                    log.exception(
                        "STAP command handler exception occurred (command "
                        "%s args %r).", command, arguments
                    )

        return response


class Analyzer:
    """Cuckoo Linux Analyzer.

    This class handles the initialization and execution of the analysis
    procedure, including the auxiliary modules and the analysis packages.
    """

    def __init__(self):
        self.config = None
        self.target = None
        self.files = Files()

    def prepare(self):
        """Prepare env for analysis."""

        # Create the folders used for storing the results.
        create_folders()

        # Initialize logging.
        init_logging()

        # Parse the analysis configuration file generated by the agent.
        self.config = Config(cfg="analysis.conf")

        if self.config.get("clock", None):
            # Set virtual machine clock.
            clock = datetime.datetime.strptime(self.config.clock, "%Y%m%dT%H:%M:%S")
            # Setting date and time.
            os.system("date -s \"{0}\"".format(clock.strftime("%y-%m-%d %H:%M:%S")))

        # We update the target according to its category. If it's a file, then
        # we store the path.
        if self.config.category == "file":
            self.target = os.path.join(tempfile.gettempdir(), self.config.file_name)
        # If it's a URL, well.. we store the URL.
        else:
            self.target = self.config.target

    def complete(self):
        """End analysis."""
        # Hell yeah.
        log.info("Analysis completed.")

    def run(self):
        """Run analysis.
        @return: operation status.
        """
        global STAP_PROC_PATH
        global PRESERVE_SUFFIX
        self.prepare()

        log.debug("Starting analyzer from: %s", os.getcwd())
        log.debug("Storing results at: %s", PATHS["root"])

        # If no analysis package was specified at submission, we try to select
        # one automatically.
        if not self.config.package:
            log.debug("No analysis package specified, trying to detect "
                      "it automagically.")

            if self.config.category == "file":
                package = "generic"
            else:
                package = "wget"

            # If we weren't able to automatically determine the proper package,
            # we need to abort the analysis.
            if not package:
                raise CuckooError("No valid package available for file "
                                  "type: {0}".format(self.config.file_type))

            log.info("Automatically selected analysis package \"%s\"", package)
        # Otherwise just select the specified package.
        else:
            package = self.config.package

        # Generate the package path.
        package_name = "modules.packages.%s" % package

        # Try to import the analysis package.
        try:
            __import__(package_name, globals(), locals(), ["dummy"], -1)
        # If it fails, we need to abort the analysis.
        except ImportError:
            raise CuckooError("Unable to import package \"{0}\", does "
                              "not exist.".format(package_name))

        # Initialize the package parent abstract.
        Package()

        # Enumerate the abstract subclasses.
        try:
            package_class = Package.__subclasses__()[0]
        except IndexError as e:
            raise CuckooError("Unable to select package class "
                              "(package={0}): {1}".format(package_name, e))

        # Initialize the analysis package.
        pack = package_class(self.config.get_options())

        # Initialize Auxiliary modules
        Auxiliary()
        prefix = auxiliary.__name__ + "."
        for loader, name, ispkg in pkgutil.iter_modules(auxiliary.__path__, prefix):
            if ispkg:
                continue

            # Import the auxiliary module.
            try:
                __import__(name, globals(), locals(), ["dummy"], -1)
                PRESERVE_SUFFIX = ".old"
                STAP_PROC_PATH = "cuckoo"
            except ImportError as e:
                log.warning("Unable to import the auxiliary module "
                            "\"%s\": %s", name, e)

        # Walk through the available auxiliary modules.
        aux_enabled, aux_avail = [], []
        for module in sorted(Auxiliary.__subclasses__(), key=lambda x: x.priority, reverse=True):
            # Try to start the auxiliary module.
            try:
                aux = module()
                aux_avail.append(aux)
                aux.start()
            except (NotImplementedError, AttributeError):
                log.warning("Auxiliary module %s was not implemented",
                            aux.__class__.__name__)
                continue
            except Exception as e:
                log.warning("Cannot execute auxiliary module %s: %s",
                            aux.__class__.__name__, e)
                continue
            finally:
                log.debug("Started auxiliary module %s",
                          aux.__class__.__name__)
                aux_enabled.append(aux)

        # Initialize and start the Command Handler STAP server.
        file_handle = None
        try:
            file_handle = open("/proc/" + STAP_PROC_PATH, "r")
            log.debug(STAP_PROC_PATH)
        except Exception as e:
            log.error(e)

        if not file_handle:
            log.error("cannot open proc file")
        self.command_stap = STAPServer(
            STAPDispatcher, file_handle,
            dispatcher=CommandSTAPHandler(self)
        )
        self.command_stap.daemon = True
        self.command_stap.start()

        # Start analysis package. If for any reason, the execution of the
        # analysis package fails, we have to abort the analysis.
        try:
            pids = pack.start(self.target)
        except NotImplementedError:
            raise CuckooError("The package \"{0}\" doesn't contain a run "
                              "function.".format(package_name))
        except CuckooPackageError as e:
            raise CuckooError("The package \"{0}\" start function raised an "
                              "error: {1}".format(package_name, e))
        except Exception as e:
            raise CuckooError("The package \"{0}\" start function encountered "
                              "an unhandled exception: "
                              "{1}".format(package_name, e))

        # If the analysis package returned a list of process IDs, we add them
        # to the list of monitored processes and enable the process monitor.
        if pids:
            add_pids(pids)
            pid_check = True

        # If the package didn't return any process ID (for example in the case
        # where the package isn't enabling any behavioral analysis), we don't
        # enable the process monitor.
        else:
            log.info("No process IDs returned by the package, running "
                     "for the full timeout.")
            pid_check = False

        # Check in the options if the user toggled the timeout enforce. If so,
        # we need to override pid_check and disable process monitor.
        if self.config.enforce_timeout:
            log.info("Enabled timeout enforce, running for the full timeout.")
            pid_check = False

        time_counter = 0

        while True:
            time_counter += 1
            if time_counter == int(self.config.timeout):
                log.info("Analysis timeout hit, terminating analysis.")
                break

            try:
                # If the process monitor is enabled we start checking whether
                # the monitored processes are still alive.
                if pid_check:
                    for pid in list(PROCESS_LIST):
                        if not Process(pid=pid).is_alive():
                            log.info("Process with pid %s has terminated", pid)
                            PROCESS_LIST.remove(pid)

                    # ask the package if it knows any new pids
                    add_pids(pack.get_pids())

                    # also ask the auxiliaries
                    for aux in aux_avail:
                        add_pids(aux.get_pids())

                    # If none of the monitored processes are still alive, we
                    # can terminate the analysis.
                    if not PROCESS_LIST:
                        log.info("Process list is empty, "
                                 "terminating analysis.")
                        break

                    # Update the list of monitored processes available to the
                    # analysis package. It could be used for internal
                    # operations within the module.
                    pack.set_pids(PROCESS_LIST)

                try:
                    # The analysis packages are provided with a function that
                    # is executed at every loop's iteration. If such function
                    # returns False, it means that it requested the analysis
                    # to be terminate.
                    if not pack.check():
                        log.info("The analysis package requested the "
                                 "termination of the analysis.")
                        break

                # If the check() function of the package raised some exception
                # we don't care, we can still proceed with the analysis but we
                # throw a warning.
                except Exception as e:
                    log.warning("The package \"%s\" check function raised "
                                "an exception: %s", package_name, e)
            except Exception as e:
                log.exception("The PID watching loop raised an exception: %s", e)
            finally:
                # Zzz.
                time.sleep(1)

        try:
            # Before shutting down the analysis, the package can perform some
            # final operations through the finish() function.
            pack.finish()
        except Exception as e:
            log.warning("The package \"%s\" finish function raised an "
                        "exception: %s", package_name, e)

        try:
            # Upload files the package created to package_files in the results folder
            package_files = pack.package_files()
            if package_files is not None:
                for package in package_files:
                    upload_to_host(
                        package[0], os.path.join("package_files", package[1])
                    )
        except Exception as e:
            log.warning("The package \"%s\" package_files function raised an "
                        "exception: %s", package_name, e)

        # stop STAPServer before stopped STAP module
        self.command_stap.stop()
        log.info("stop STAPServer")

        # Terminate the Auxiliary modules.
        for aux in sorted(aux_enabled, key=lambda x: x.priority):
            try:
                aux.stop()
            except (NotImplementedError, AttributeError):
                continue
            except Exception as e:
                log.warning("Cannot terminate auxiliary module %s: %s",
                            aux.__class__.__name__, e)

        if self.config.terminate_processes:
            # Try to terminate remaining active processes. We do this to make sure
            # that we clean up remaining open handles (sockets, files, etc.).
            log.info("Terminating remaining processes before shutdown.")

            for pid in PROCESS_LIST:
                proc = Process(pid=pid)
                if proc.is_alive():
                    try:
                        proc.terminate()
                    except:
                        continue

        # Run the finish callback of every available Auxiliary module.
        for aux in aux_avail:
            try:
                aux.finish()
            except (NotImplementedError, AttributeError):
                continue
            except Exception as e:
                log.warning("Exception running finish callback of auxiliary "
                            "module %s: %s", aux.__class__.__name__, e)


        # Dump all the notified files.
        self.files.dump_files()
        # Let's invoke the completion procedure.
        self.complete()

        return True

if __name__ == "__main__":
    success = False
    error = ""

    try:
        # Initialize the main analyzer class.
        analyzer = Analyzer()

        # Run it and wait for the response.
        success = analyzer.run()

    # This is not likely to happen.
    except KeyboardInterrupt:
        error = "Keyboard Interrupt"

    # If the analysis process encountered a critical error, it will raise a
    # CuckooError exception, which will force the termination of the analysis.
    # Notify the agent of the failure. Also catch unexpected exceptions.
    except Exception as e:
        # Store the error.
        error_exc = traceback.format_exc()
        error = str(e)

        # Just to be paranoid.
        if len(log.handlers):
            log.exception(error_exc)
        else:
            sys.stderr.write("{0}\n".format(error_exc))

    # Once the analysis is completed or terminated for any reason, we report
    # back to the agent, notifying that it can report back to the host.
    finally:
        try:
            # old agent
            server = xmlrpclib.Server("http://127.0.0.1:8000")
            server.complete(success, error, PATHS["root"])
        except xmlrpclib.ProtocolError:
            # new agent
            data = {
                "status": "complete",
                "description": success
            }
            urllib2.urlopen(
                "http://127.0.0.1:8000/status", urllib.urlencode(data)
            )
