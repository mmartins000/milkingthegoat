#
# Milking the Goat
# Author: Marcelo Martins
# Source: https://github.com/mmartins000/milkingthegoat
#
# Pre-requisites:
# Python modules GitPython, Docker
# Internet access to download container images and clone Git repos

import time
import datetime
import argparse
import sys
import os
from pathlib import Path
import json

from git import Repo
import docker
from docker import errors

# Hardcoded variables:
__version__ = '0.1.1'

# Default exit signals can be changed using config file
EXIT_OK = 0
EXIT_FAIL_LOW = 1
EXIT_FAIL_MEDIUM = 2
EXIT_FAIL_HIGH = 3

# Hardcoded signals
EXIT_NOOP = 10
EXIT_ROOT = 11
EXIT_NOT_WRITABLE = 12
EXIT_FILE_NOT_FOUND = 13
EXIT_INVALID_SOURCE = 14
EXIT_INVALID_CONFIG = 15
EXIT_FILE_FORMAT = 16
EXIT_JSON_FILE = 17


def print_version():
    log_and_print("info", "\nMilking the Goat v{}\n".format(__version__))
    return True  # Do not remove, used in main scope, in-line condition


def running_as_root():
    log_and_print("critical", "To reduce risks, do not run as root. To ignore this warning, use flag --ignore-root.")
    sys.exit(EXIT_ROOT)


def dest_not_writable(dest):
    log_and_print("critical", "Error: Destination is not writable: {}".format(dest))
    sys.exit(EXIT_NOT_WRITABLE)


def invalid_source(source):
    log_and_print("critical", "Error: {} is not a valid directory.".format(source))
    sys.exit(EXIT_INVALID_SOURCE)


def missing_config(config_file):
    log_and_print("critical", "Error: Could not locate config file: {}".format(config_file))
    sys.exit(EXIT_INVALID_CONFIG)


def noop():
    log_and_print("info", "All scans skipped and clean up is not set. Nothing to do here.")
    sys.exit(EXIT_NOOP)


def sanity_checks():
    """
    Runs a few basic checks before start scanning, not to waste users' time.
    Pythonic way is EAFP: https://docs.python.org/3/glossary.html#term-EAFP
    Called by main().
    :return:
    """
    # Check if running as root (should not):
    args.ignoreRoot or os.geteuid() == 0 and running_as_root()

    # Check if an operation was selected:
    (args.skipKics and args.skipCheckov and args.skipTfsec and args.skipTerrascan and args.skipTrivy
     and not args.cleanup) and noop()


def is_url(str_url):
    """
    If this is a valid URL, we will try to clone it locally.
    The user is supposed to use a Git clone URL. This is 'best effort'. I'm just checking to avoid errors.
    Called by run_scan().
    :param str_url: Destination string, supposedly a URL
    :return: True if is a valid URL; otherwise, False
    """
    from urllib.parse import urlparse
    import urllib.error
    try:
        o = urlparse(str_url)
        if o.scheme and o.netloc and o.path:
            return True
        return False
    except urllib.error.URLError:
        return False


def clone_repo(source_dir):
    """
    Runs Git module to clone a repo locally.
    Called by run_scan().
    :param source_dir: Comes from args.source
    :return: True if successful or exits with error code
    """
    log_and_print("info", "Cloning repository in " + dest_clones)

    # This is an attempt to automate the naming convention for a local folder where a Git repo will be cloned
    # Example: https://github.com/user/repo.git --> repo
    # I'm not locking it with 'github.com' because the user might have another Git repo somewhere else.
    # For this to work, the user must enter a Git clone URL (with .git in the end)
    local_folder = os.path.basename(os.path.normpath(args.source)).replace(".git", "")
    try:
        # git clone [repo]
        repo_to_clone = dest_clones + "/" + local_folder
        if not os.path.isdir(repo_to_clone):
            log_and_print("debug", "Cloning repository {}.".format(repo_to_clone))
            Repo.clone_from(source_dir, repo_to_clone)
        else:
            log_and_print("debug", "Repo {} has already been cloned.".format(repo_to_clone))

        return local_folder
    except PermissionError:
        dest_not_writable(dest_clones)


def clone_goats():
    """
    Runs Git module to clone Goats locally.
    Called by run_scan().
    :return: True if successful or exits with error code
    """
    # To fully automate this function using config file, I would need a 2D array, with the local name and Github URL
    # not os.access(dest_clones, os.W_OK) and dest_not_writable(dest_clones)

    log_and_print("info", "Cloning the Goats in " + dest_clones)

    from git import exc
    try:
        json_goats = get_goats(goats_file)
        for target in json_goats["targets"]:
            local_folder = target["local_folder"]
            # Avoid cloning an already cloned repo
            repo_to_clone = dest_clones + "/" + local_folder
            if not os.path.isdir(repo_to_clone):
                log_and_print("debug", "Cloning repository {}.".format(repo_to_clone))
                Repo.clone_from(target["source"], repo_to_clone)
            else:
                log_and_print("debug", "Repo {} has already been cloned.".format(repo_to_clone))
    except (PermissionError, exc.GitCommandError):
        dest_not_writable(dest_clones)


def docker_save_log(str_log, output_file):
    try:
        with open(output_file, 'w') as f:
            try:
                res = json.loads(str_log)
                json.dump(res, f, indent=4)
            except json.decoder.JSONDecodeError:
                log_and_print("error", "Error: Could not understand stdout data.".format(output_file))
                return False
    except FileNotFoundError:
        log_and_print("error", "Error: Could not write to file {}.".format(output_file))
        return False


def run_docker_checkov(source_directory, force_docker_pull):
    """
    Runs Docker Checkov container.
    Called by run_scan().
    :param source_directory: The directory where the apps will perform their security assessment.
    :param force_docker_pull: If Docker should always download an image or not.
    :return: True
    """
    if not args.skipCheckov:
        log_and_print("info", "Running Checkov on {}...".format(source_directory))

        docker_pull_image(docker_image_checkov, force_docker_pull)
        start = time.time()

        # Checkov: If Docker runs with flag --tty, it will generate non-printable characters at the end of JSON output.
        # Ref: https://www.checkov.io/4.Integrations/Docker.html

        dc = docker.from_env()
        container_id = dc.api.create_container(
            image=docker_image_checkov,
            command="--quiet -d /src --output {}".format(output_format_checkov),
            volumes=['/src'],
            host_config=dc.api.create_host_config(binds={
                source_directory: {
                    'bind': '/src',
                    'mode': 'ro',
                }
            })
        )
        dc.api.start(container_id)
        dc.api.wait(container_id)
        # Saves the output into a JSON file (there is no output flag in command)
        docker_save_log(dc.api.logs(container_id).decode('utf-8'), results_checkov)

        end = time.time()
        total_time = str(round(end - start, 2)) + " seconds"
        str_it_took = ", it took " + total_time
        log_and_print("info", "Docker ran Checkov container in {}{} and the report was saved in {}."
                      .format(source_directory, str_it_took, results_checkov))

        process_checkov(load_from_json(results_checkov), results_checkov,
                        os.path.basename(os.path.normpath(source_directory)), total_time)


def run_docker_tfsec(source_directory, force_docker_pull):
    """
    Runs Docker tfsec container.
    Called by run_scan().
    :param source_directory: The directory where the apps will perform their security assessment.
    :param force_docker_pull: If Docker should always download an image or not.
    :return: True
    """
    # Ref: https://aquasecurity.github.io/tfsec/v1.4.2/getting-started/usage/
    if not args.skipTfsec:
        log_and_print("info", "Running tfsec on {}...".format(source_directory))

        docker_pull_image(docker_image_tfsec, force_docker_pull)
        start = time.time()

        # Used because the results volume was mounted
        results_tfsec_output_dir = results_tfsec.rstrip("/").rsplit('/', 1)[0]
        # results_tfsec_output_dir_file = "/results/" + results_tfsec_filename

        dc = docker.from_env()
        container_id = dc.api.create_container(
            image=docker_image_tfsec,
            command="/src --no-colour --format {} --out {}".format(output_format_tfsec, results_tfsec_filename),
            volumes=['/src'],
            host_config=dc.api.create_host_config(binds={
                source_directory: {
                    'bind': '/src',
                    'mode': 'ro',
                },
                results_tfsec_output_dir: {
                    'bind': '/results',
                    'mode': 'rw',
                }
            })
        )
        dc.api.start(container_id)
        dc.api.wait(container_id)
        # Not necessary, results volume mounted and used in command
        # docker_save_log(dc.api.logs(container_id).decode('utf-8'), results_tfsec)

        end = time.time()
        total_time = str(round(end - start, 2)) + " seconds"
        str_it_took = ", it took " + total_time
        log_and_print("info", "Docker ran tfsec container in {}{} and the report was saved in {}."
                      .format(source_directory, str_it_took, results_tfsec))

        process_tfsec(load_from_json(results_tfsec), results_tfsec,
                      os.path.basename(os.path.normpath(source_directory)), total_time)


def run_docker_kics(source_directory, force_docker_pull):
    """
    Runs Docker KICS container.
    Called by run_scan().
    :param source_directory: The directory where the apps will perform their security assessment.
    :param force_docker_pull: If Docker should always download an image or not.
    :return: True
    """
    if not args.skipKics:
        log_and_print("info", "Running KICS on {}...".format(source_directory))

        docker_pull_image(docker_image_kics, force_docker_pull)
        start = time.time()

        # KICS can save in different formats and the stdout output is different from JSON object
        # Output will be saved with filename 'results.json' (if output-format is JSON)
        # Because KICS is doing the output, I need to mount another volume for default results folder, otherwise
        # there will be no output, although KICS outputs a message to sdtout saying the output was successful
        # Ref: https://github.com/Checkmarx/kics/blob/master/docs/commands.md

        # Used because the results volume was mounted
        results_kics_output_dir = results_kics.rstrip("/").rsplit('/', 1)[0]
        # results_kics_output_dir_file = "/results/" + results_kics_filename

        dc = docker.from_env()
        container_id = dc.api.create_container(
            image=docker_image_kics,
            command="scan -p \"/src\" --silent --no-color --report-formats {} --output-path \"/results\""
                    .format(output_format_kics),
            volumes=['/src', '/results'],
            host_config=dc.api.create_host_config(binds={
                source_directory: {
                    'bind': '/src',
                    'mode': 'ro',
                },
                results_kics_output_dir: {
                    'bind': '/results',
                    'mode': 'rw',
                }
            })
        )
        dc.api.start(container_id)
        dc.api.wait(container_id)
        # Not necessary, results volume mounted and used in command
        # docker_save_log(dc.api.logs(container_id).decode('utf-8'), results_kics)

        end = time.time()
        total_time = str(round(end - start, 2)) + " seconds"
        str_it_took = ", it took " + total_time
        log_and_print("info", "Docker ran KICS container in {}{} and the report was saved in {}."
                      .format(source_directory, str_it_took, results_kics.rsplit('/', 1)[0] + "/results.json"))

        process_kics(load_from_json(results_kics), results_kics,
                     os.path.basename(os.path.normpath(source_directory)), total_time)


def run_docker_terrascan(source_directory, force_docker_pull):
    """
    Runs Docker Terrascan container.
    Called by run_scan().
    :param source_directory: The directory where the apps will perform their security assessment.
    :param force_docker_pull: If Docker should always download an image or not.
    :return: True
    """
    if not args.skipTerrascan:
        log_and_print("info", "Running Terrascan on {}...".format(source_directory))

        docker_pull_image(docker_image_terrascan, force_docker_pull)
        start = time.time()

        # Because I could not find a flag for output, I'm capturing the output from stdout to make a JSON file.
        # Flag '-x console' (default) makes errors go into the console
        # Flag '--log-level fatal' avoids logging at the console not to mess with JSON output
        # Flag '-o' selects an output format
        # Ref: https://runterrascan.io/docs/usage/command_line_mode/

        dc = docker.from_env()
        container_id = dc.api.create_container(
            image=docker_image_terrascan,
            command="scan -d /src -x console --use-colors f --log-level fatal -o {}"
                    .format(output_format_terrascan),
            volumes=['/src'],
            host_config=dc.api.create_host_config(binds={
                source_directory: {
                    'bind': '/src',
                    'mode': 'ro',
                }
            })
        )
        dc.api.start(container_id)
        dc.api.wait(container_id)
        # Saves the output into a JSON file (there is no output flag in command)
        docker_save_log(dc.api.logs(container_id).decode('utf-8'), results_terrascan)

        end = time.time()
        total_time = str(round(end - start, 2)) + " seconds"
        str_it_took = ", it took " + total_time
        log_and_print("info", "Docker ran Terrascan container in {}{} and the report was saved in {}."
                      .format(source_directory, str_it_took, results_terrascan))

        process_terrascan(load_from_json(results_terrascan), results_terrascan,
                          os.path.basename(os.path.normpath(source_directory)), total_time)


def run_docker_trivy(source_directory, force_docker_pull):
    """
    Runs Docker Trivy container.
    Called by run_scan().
    :param source_directory: The directory where the apps will perform their security assessment.
    :param force_docker_pull: If Docker should always download an image or not.
    :return: True
    """
    if not args.skipTrivy:
        log_and_print("info", "Running Trivy on {}...".format(source_directory))

        docker_pull_image(docker_image_trivy, force_docker_pull)
        start = time.time()

        # Trivy can save in different formats and the stdout output is different from JSON object
        # Output will be saved with filename 'results-trivy.json' (if output-format is JSON)
        # Because Trivy is doing the output, I need to mount another volume for default results folder, otherwise
        # there will be no output

        # Ref: https://aquasecurity.github.io/trivy/v0.24.1/getting-started/cli/config/

        # Used because the results volume was mounted
        results_trivy_output_dir = results_trivy.rstrip("/").rsplit('/', 1)[0]
        results_volume_filename = "/results/{}".format(results_trivy_filename)
        results_trivy_output_dir_file = results_trivy_output_dir + "/" + results_trivy_filename

        dc = docker.from_env()
        container_id = dc.api.create_container(
            image=docker_image_trivy,
            command="-q config -f {} -o {} \"/src\"".format(output_format_trivy, results_volume_filename),
            volumes=['/src', '/results'],
            host_config=dc.api.create_host_config(binds={
                source_directory: {
                    'bind': '/src',
                    'mode': 'ro',
                },
                results_trivy_output_dir: {
                    'bind': '/results',
                    'mode': 'rw',
                }
            })
        )
        dc.api.start(container_id)
        dc.api.wait(container_id)
        # Not necessary, results volume mounted and used in command
        # docker_save_log(dc.api.logs(container_id).decode('utf-8'), results_trivy)

        end = time.time()
        total_time = str(round(end - start, 2)) + " seconds"
        str_it_took = ", it took " + total_time
        log_and_print("info", "Docker ran Trivy container in {}{} and the report was saved in {}."
                      .format(source_directory, str_it_took, results_trivy_output_dir_file))

        process_trivy(load_from_json(results_trivy_output_dir_file), results_trivy_output_dir_file,
                      os.path.basename(os.path.normpath(source_directory)), total_time)


def run_scan():
    """
    Decides how the app is going to run (Goats or local project), calls clone functions, calls Docker functions.
    Called by main().
    :return: True if cloning is successful; False if PermissionError exception raised
    """
    global results_checkov, results_tfsec, results_kics, results_terrascan, results_trivy

    args.verbose and print_version()

    if args.forceDockerPull:
        force_docker_pull = "always"
    else:
        force_docker_pull = "missing"

    # If the user did not provide a source directory, we will check for a benchmark against the Goats or Locals
    if not args.source:

        # Goats or Locals?
        if args.locals:  # Domestic goats
            json_iterable = get_goats(local_file)
        else:  # args.goats == True, Foreign Goats
            json_iterable = get_goats(goats_file)
            clone_goats()

        log_and_print("info", "Starting IaC code scans...")

        for target in json_iterable["targets"]:
            local_folder = target["local_folder"]
            source = str(dest_clones + "/" + local_folder).replace("//", "/")
            results_dir = str(results_destination + "/" + local_folder).replace("//", "/")

            # Create results directories for each Goat
            try:
                Path(results_dir).mkdir(parents=True, exist_ok=True)
            except FileExistsError:
                # Should not be called due to 'exist_ok=True'
                log_and_print("debug", "Folder {} already exists.".format(results_dir))
            except PermissionError:
                dest_not_writable(results_dir)

            # Declared outside; here for the 'for goat in goats' loop
            results_checkov = \
                str(results_destination + "/" + local_folder + "/" + results_checkov_filename).replace("//", "/")
            results_tfsec = \
                str(results_destination + "/" + local_folder + "/" + results_tfsec_filename).replace("//", "/")
            results_kics = \
                str(results_destination + "/" + local_folder + "/" + results_kics_filename).replace("//", "/")
            results_terrascan = \
                str(results_destination + "/" + local_folder + "/" + results_terrascan_filename).replace("//", "/")
            results_trivy = \
                str(results_destination + "/" + local_folder + "/" + results_trivy_filename).replace("//", "/")

            # Run the tools
            run_docker_checkov(source, force_docker_pull)
            run_docker_tfsec(source, force_docker_pull)
            run_docker_kics(source, force_docker_pull)
            run_docker_terrascan(source, force_docker_pull)
            run_docker_trivy(source, force_docker_pull)

        log_and_print("info", "Finished scanning IaC code.")

    else:
        # The user provided a URL or a source directory.
        if is_url(args.source):
            # The user provided a URL.
            local_folder = clone_repo(args.source)
            source = str(dest_clones + "/" + local_folder).replace("//", "/")

            # Create results directory for this assessment
            # Declared outside; results_destination is the default folder for reports
            results_local_folder = results_destination + "/" + local_folder
        else:
            # The user provided a source directory
            os.path.isdir(args.source) or invalid_source(args.source)
            # dest_clones is the default destination for Goat clones
            local_folder = args.source  # Here, the user is picking a full path
            source = str(local_folder).replace("//", "/")
            # Declared outside; results_destination is the default folder for reports
            results_local_folder = results_destination + "/" + str(local_folder).rstrip("/").rsplit("/", 1)[1]

        log_and_print("info", "Starting IaC code scans...")

        try:
            if not os.path.isdir(results_local_folder):
                log_and_print("debug", "Creating folder {}.".format(results_local_folder))
                Path(results_local_folder).mkdir(parents=True, exist_ok=True)
        except FileExistsError:
            # If the folder exists, we will use it
            log_and_print("debug", "Folder {} already exists.".format(results_local_folder))
        except PermissionError:
            dest_not_writable(results_local_folder)

        results_checkov = results_local_folder + "/" + results_checkov_filename
        results_tfsec = results_local_folder + "/" + results_tfsec_filename
        results_kics = results_local_folder + "/" + results_kics_filename
        results_terrascan = results_local_folder + "/" + results_terrascan_filename
        results_trivy = results_local_folder + "/" + results_trivy_filename

        run_docker_checkov(source, force_docker_pull)
        run_docker_tfsec(source, force_docker_pull)
        run_docker_kics(source, force_docker_pull)
        run_docker_terrascan(source, force_docker_pull)
        run_docker_trivy(source, force_docker_pull)

        log_and_print("info", "Finished scanning IaC code.")


def process_checkov(json_object, json_filename, source, total_time):
    """
    Processes Checkov JSON output and collects summary data
    :param json_object: JSON data loaded from file
    :param json_filename: The name of the file that contained the data
    :param source: The last directory in the path
    :param total_time: The time it took to run Checkov
    :return: True if JSON structure was readable (and parsed), False otherwise
    """
    # If we failed to load the file as a JSON object (in function load_from_json()), stop
    if not json_object:
        return

    global json_milk

    # Now, does the file have the structure we're looking for?
    try:
        for item in json_object:
            str_check = item["check_type"]
            str_passed = item["summary"]["passed"]
            str_failed = item["summary"]["failed"]
            str_skipped = item["summary"]["skipped"]
            str_version = item["summary"]["checkov_version"]

            # Scan-specific data to be written
            json_checkov_check = {
                "passed": str_passed,
                "failed": str_failed,
                "skipped": str_skipped
            }

            # If we're here, we were able to collect the info for that check_type into 'data' variable
            # Let's append it to the main 'stash' and look for other check_types
            try:
                json_milk[source]["checkov"][str_check] = {}
            except KeyError:
                try:
                    json_milk[source]["checkov"] = {
                        "json_file": json_filename,
                        "version": str_version,
                        "running_time": total_time
                    }
                    json_milk[source]["checkov"][str_check] = {}
                except KeyError:
                    pass
            finally:
                json_milk[source]["checkov"][str_check].update(json_checkov_check)
    except TypeError:
        # It doesn't, but maybe Checkov doesn't have policies for that type of file
        # So, we won't find 'check_type' there. Let's search for 'passed', 'failed', 'skipped'
        try:
            if json_object["passed"] == 0 and json_object["failed"] == 0 and json_object["skipped"] == 0:
                json_checkov = {
                    "check_type": "none"
                }
                json_milk[source]["checkov"] = {}
                json_milk[source]["checkov"]["none"] = {}
                json_milk[source]["checkov"]["none"].update(json_checkov)

                log_and_print("warn", "Warning: Checkov could not process this application.")
        except (KeyError, TypeError):
            # No, there is something wrong with this file
            log_and_print("error", "Error: could not process this file: {}".format(json_filename))


def process_tfsec(json_object, json_filename, source, total_time):
    """
    Processes tfsec JSON output and collects summary data
    :param json_object: JSON data loaded from file
    :param json_filename: The name of the file that contained the data
    :param source: The last directory in the path
    :param total_time: The time it took to run tfsec
    :return: True if JSON structure was readable (and parsed), False otherwise
    """
    # If we failed to load the file as a JSON object (in function load_from_json()), stop
    if not json_object:
        return

    global json_milk
    str_failed, str_high, str_medium, str_low = 0, 0, 0, 0
    try:
        for item in json_object["results"]:
            str_failed += 1
            if item["severity"] == "HIGH":
                str_high += 1
            elif item["severity"] == "MEDIUM":
                str_medium += 1
            elif item["severity"] == "LOW":
                str_low += 1

        json_tfsec = {
            "json_file": json_filename,
            "version": get_version_tfsec(),
            "running_time": total_time,
            "check_type": "terraform",  # Hardcoded because tfsec scans Terraform code only
            "passed": 0,
            "skipped": 0,
            "failed": str_failed,
            "failed_by_severity": {
                "high": str_high,
                "medium": str_medium,
                "low": str_low
            }
        }
        json_milk[source]["tfsec"] = {}
        json_milk[source]["tfsec"].update(json_tfsec)
    except TypeError:
        try:
            if json_object["results"] == "null":
                json_tfsec = {
                    "json_file": json_filename,
                    "version": get_version_tfsec(),
                    "running_time": total_time,
                    "check_type": "none",
                    "passed": 0,
                    "failed": 0,
                    "skipped": 0
                }
                json_milk[source]["tfsec"] = {}
                json_milk[source]["tfsec"].update(json_tfsec)

                log_and_print("warn", "Warning: tfsec did not process this application.")
        except KeyError:
            log_and_print("error", "Error: could not process this file: {}".format(json_filename))


def process_kics(json_object, json_filename, source, total_time):
    """
    Processes KICS JSON output and collects summary data
    :param json_object: JSON data loaded from file
    :param json_filename: The name of the file that contained the data
    :param source: The last directory in the path
    :param total_time: The time it took to run KICS
    :return: True if JSON structure was readable (and parsed), False otherwise
    """
    # If we failed to load the file as a JSON object (in function load_from_json()), stop
    if not json_object:
        return

    global json_milk

    # Now, does the file have the structure we're looking for?
    try:
        # KICS flags INFO severity checks like "Variables are not snake case"
        # To make comparison easier, I'm removing INFO and TRACE severity from the count
        str_high = json_object["severity_counters"]["HIGH"]
        str_medium = json_object["severity_counters"]["MEDIUM"]
        str_low = json_object["severity_counters"]["LOW"]
        str_failed = int(str_high) + int(str_medium) + int(str_low)
        # I'm also excluding INFO from the total (passed), like it never happened
        str_passed = json_object["queries_total"] - str_failed - json_object["severity_counters"]["INFO"]
        str_skipped = json_object["queries_failed_to_execute"]
        str_version = json_object["kics_version"]

        # Data to be written
        json_kics = {
            "json_file": json_filename,
            "version": str_version,
            "running_time": total_time,
            "skipped": str_skipped,
            "passed": str_passed,
            "failed": str_failed,
            "failed_by_severity": {
                "high": str_high,
                "medium": str_medium,
                "low": str_low
            }
        }

        # If we're here, we were able to collect the info for that check_type into 'data' variable
        # Let's append it to the main 'stash' and look for other check_types
        json_milk[source]["kics"] = {}
        json_milk[source]["kics"].update(json_kics)
    except (KeyError, TypeError):
        # It doesn't, but maybe KICS doesn't have policies for that type of file
        # So, we won't find 'check_type' there. Let's search for 'passed', 'failed', 'skipped'
        try:
            if json_object["passed"] == 0 and json_object["failed"] == 0 and json_object["skipped"] == 0:
                json_kics = {
                    "json_file": json_filename,
                    "check_type": "none"
                }
                json_milk[source]["kics"] = {}
                json_milk[source]["kics"].update(json_kics)
                log_and_print("warn", "Warning: KICS could not process this application.")
        except (KeyError, TypeError):
            # No, there is something wrong with this file
            log_and_print("error", "Error: could not process this file: {}".format(json_filename))


def process_terrascan(json_object, json_filename, source, total_time):
    """
    Processes Terrascan JSON output and collects summary data
    :param json_object: JSON data loaded from file
    :param json_filename: The name of the file that contained the data
    :param source: The last directory in the path
    :param total_time: The time it took to run Terrascan
    :return: True if JSON structure was readable (and parsed), False otherwise
    """
    # If we failed to load the file as a JSON object (in function load_from_json()), stop
    if not json_object:
        return

    global json_milk
    try:
        str_skipped = json_object["results"]["skipped_violations"]
        str_check = json_object["results"]["scan_summary"]["iac_type"]
        str_passed = json_object["results"]["scan_summary"]["policies_validated"]
        str_failed = json_object["results"]["scan_summary"]["violated_policies"]
        str_low = json_object["results"]["scan_summary"]["low"]
        str_medium = json_object["results"]["scan_summary"]["medium"]
        str_high = json_object["results"]["scan_summary"]["high"]

        json_terrascan = {
            "json_file": json_filename,
            "version": get_version_terrascan(),
            "check_type": str_check,
            "running_time": total_time,
            "skipped": str_skipped,
            "passed": str_passed,
            "failed": str_failed,
            "failed_by_severity": {
                "high": str_high,
                "medium": str_medium,
                "low": str_low
            }
        }

        json_milk[source]["terrascan"] = {}
        json_milk[source]["terrascan"].update(json_terrascan)
    except TypeError:
        log_and_print("warn", "Warning: Terrascan could not process this application.")
    except KeyError:
        log_and_print("error", "Error: could not process this file: {}".format(json_filename))


def process_trivy(json_object, json_filename, source, total_time):
    """
    Processes Trivy JSON output and collects summary data.
    Tested with Trivy v0.24.1, which is very buggy.
    ---> Raised fatal errors with Terragoat and CfnGoat.

    :param json_object: JSON data loaded from file
    :param json_filename: The name of the file that contained the data
    :param source: The last directory in the path
    :param total_time: The time it took to run Trivy
    :return: True if JSON structure was readable (and parsed), False otherwise
    """
    # If we failed to load the file as a JSON object (in function load_from_json()), stop
    if not json_object:
        return

    global json_milk
    str_passed, str_failed, str_skipped, str_high, str_medium, str_low = 0, 0, 0, 0, 0, 0
    check_type = []
    try:
        for assessed_file in json_object["Results"]:
            check_type.append(assessed_file["Type"])
            str_passed += assessed_file["MisconfSummary"]["Successes"]
            str_failed += assessed_file["MisconfSummary"]["Failures"]
            str_skipped += assessed_file["MisconfSummary"]["Exceptions"]
            if assessed_file["MisconfSummary"]["Failures"] > 0:
                for misconfiguration in assessed_file["Misconfigurations"]:
                    if misconfiguration["Severity"] == "HIGH":
                        str_high += 1
                    elif misconfiguration["Severity"] == "MEDIUM":
                        str_medium += 1
                    elif misconfiguration["Severity"] == "LOW":
                        str_low += 1

        # Select unique values then sort
        check_type = list(set(check_type))
        check_type.sort()

        json_trivy = {
            "json_file": json_filename,
            "version": get_version_trivy(),
            "running_time": total_time,
            "check_type": check_type,
            "passed": str_passed,
            "skipped": str_skipped,
            "failed": str_failed,
            "failed_by_severity": {
                "high": str_high,
                "medium": str_medium,
                "low": str_low
            }
        }
        json_milk[source]["trivy"] = {}
        json_milk[source]["trivy"].update(json_trivy)
    except TypeError:
        try:
            if json_object["results"] == "null":
                json_trivy = {
                    "json_file": json_filename,
                    "version": get_version_trivy(),
                    "running_time": total_time,
                    "check_type": "none",
                    "passed": 0,
                    "failed": 0,
                    "skipped": 0
                }
                json_milk[source]["trivy"] = {}
                json_milk[source]["trivy"].update(json_trivy)

                log_and_print("warn", "Warning: Trivy did not process this application.")
        except KeyError:
            log_and_print("error", "Error: could not process this file: {}".format(json_filename))


def load_from_json(json_filename):
    """
    Loads a text file into a JSON object.
    Called by process_checkov(), process_tfsec(), process_kics(), process_terrascan() and process_trivy().
    :param json_filename: JSON file to be processed
    :return: JSON object to passed to other functions; or False if there was an exception
    """
    try:
        with open(json_filename, 'r', encoding='utf-8') as f:
            try:
                res = json.loads(f.read())
                return res
            except json.decoder.JSONDecodeError:
                log_and_print("error", "Error: Could not decode {} as JSON data file.".format(json_filename))
                return False
    except FileNotFoundError:
        log_and_print("error", "Error: Could not find file {}.".format(json_filename))
        return False


def write_json_to_file(data, filename):
    """
    Writes JSON dict to file.
    Called by main().
    :param data: JSON object
    :param filename: Destination where data will be written
    :return: True for success, otherwise exits with error code in case of exception
    """
    # Clean up destination path
    bad_chars = "\'\""
    full_dest = results_destination + '/' + filename
    for c in bad_chars:
        full_dest = full_dest.replace(c, "")
    full_dest = full_dest.replace("//", "/")

    date_format = "%Y-%m-%d %H:%M:%S"
    data["milking_the_goat"]["end_time"] = str(datetime.datetime.now().strftime(date_format))
    dt_duration = datetime.datetime.strptime(data["milking_the_goat"]["end_time"], date_format) \
        - datetime.datetime.strptime(data["milking_the_goat"]["start_time"], date_format)
    data["milking_the_goat"]["duration_seconds"] = int(dt_duration.total_seconds())
    data["milking_the_goat"]["extended_duration"] = display_time(int(dt_duration.total_seconds()))

    try:
        Path(results_destination).mkdir(parents=True, exist_ok=True)

        with open(full_dest, 'w') as f:
            json.dump(data, f, indent=4)
            log_and_print("info", "Milking the Goat JSON saved to {}".format(full_dest))
    except PermissionError:
        dest_not_writable(full_dest)


def display_time(seconds, granularity=5):
    """
    Converts seconds in string text with weeks, days, hours, etc.
    :param seconds: The number of seconds we want to convert.
    :param granularity: How far we should go in the intervals JSON.
    :return: String
    """
    # Modified from:
    # https://stackoverflow.com/questions/4048651/python-function-to-convert-seconds-into-minutes-hours-and-days
    result = []
    intervals = (
        ('weeks', 604800),  # 60 * 60 * 24 * 7
        ('days', 86400),    # 60 * 60 * 24
        ('hours', 3600),    # 60 * 60
        ('minutes', 60),
        ('seconds', 1),
    )

    for name, count in intervals:
        value = seconds // count
        if value:
            if value >= 1:
                seconds -= value * count
                if value == 1:
                    name = name.rstrip('s')
                result.append("{} {}".format(value, name))
    return ', '.join(result[:granularity])


def create_json_structure():
    """
    Create a basic JSON object.
    Called by main().
    :return: True if main JSON object is successfully updated; otherwise, exits with error code
    """

    if bool_command_line_args:
        str_command_line_args = str(args)
    else:
        str_command_line_args = None

    try:
        dc = docker.from_env()
        if bool_docker_version:
            str_docker_version = dc.version()
        else:
            str_docker_version = None

    except docker.errors.APIError as e:
        log_and_print("error", "Error: Could not read version from Docker client.")
        str_docker_version = None

    finally:
        # JSON result file, schema version 1
        data = {
            "milking_the_goat": {
                "script_version": __version__,
                "json_schema_version": "1",
                "url": "https://github.com/mmartins000/milkingthegoat",
                "command_line_args": str_command_line_args,
                "docker_version": str_docker_version,
                "start_time": str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                "end_time": "",
                "duration": ""
            }
        }

    try:
        if not args.source:
            # Milking the well-known Goats from Github
            # Goats or Locals?
            if args.locals:  # Domestic goats
                json_iterable = get_goats(local_file)
            else:  # args.goats == True, Foreign goats
                json_iterable = get_goats(goats_file)

            for target in json_iterable["targets"]:
                json_goat = {
                    target["local_folder"]: {
                        "git_http_url": target["source"]
                    }
                }
                data.update(json_goat)
        else:
            # Milking a local Goat (local project)
            json_local = {
                str(os.path.basename(os.path.normpath(args.source)).replace(".git", "")): {
                    "source": args.source
                }
            }
            data.update(json_local)

        json_milk.update(data)

    except (TypeError, KeyError, IndexError):
        log_and_print("error", "Error: Could not read Goats from config file.")
        exit(EXIT_JSON_FILE)


def get_version_trivy():
    """
    Runs Docker to get Trivy version. Trivy JSON output doesn't contain the executable version.
    Called by process_trivy().
    :return: String with version
    """
    # Trivy outputs version in stdout as: "Version: vn.n.n"
    if not args.skipTrivy:
        return get_version(container_image=docker_image_trivy, command_to_run='--version').split(" ")[1]


def get_version_tfsec():
    """
    Runs Docker to get tfsec version. tfsec JSON output doesn't contain the executable version.
    Called by process_tfsec().
    :return: String with version
    """
    # tfsec outputs version in stdout as: "vn.n.n"
    if not args.skipTfsec:
        return get_version(container_image=docker_image_tfsec, command_to_run='--version')


def get_version_terrascan():
    """
    Runs Docker to get Terrascan version. Terrascan JSON output doesn't contain the executable version.
    Called by process_terrascan().
    :return: String with version
    """
    # Terrascan outputs version in stdout as: "version: vn.n.n"
    if not args.skipTerrascan:
        return get_version(container_image=docker_image_terrascan, command_to_run='version').split(" ")[1]


def get_version(container_image, command_to_run):
    """
    Runs Docker to get container image version.
    Called by get_version_tfsec(), get_version_terrascan() and get_version_trivy().
    :return: String containing Container version or "None"
    """
    docker_pull_image(container_image, args.forceDockerPull)

    dc = docker.from_env()
    try:
        ctn = dc.containers.run(image=container_image,
                                command=command_to_run,
                                remove=True, tty=False, detach=False)
    except docker.errors.ContainerError:
        container_version = "None"
    else:
        container_version = ctn.decode("utf-8").replace('\n', '')

    return container_version


def docker_pull_image(image_name, force_docker_pull):
    """
    Pulls the image before described in config file
    docker.containers.run() and docker.api.create_container() don't include a --pull flag
    :param image_name: Container image to be downloaded, format: 'repo/image:tag'
    :param force_docker_pull: If Docker should always download an image or not.
    :return: True if succeeded, False if exception raised
    """
    dc = docker.from_env()
    if force_docker_pull == "always":
        # We will download if --pull "always"
        log_and_print("info", "Downloading Docker image for {}.".format(image_name))
        try:
            dc.api.pull(image_name)
        except docker.errors.APIError as e:
            log_and_print("error", "{}".format(e.args))
            return False
        else:
            log_and_print("info", "Docker just downloaded image {}.".format(image_name))
    else:
        # We will check if we have the image because --pull "missing"
        found_image = False
        for image in dc.images.list(all=True):
            if image.attrs['RepoDigests'][0].split("@")[0] == image_name.split(":")[0]:
                found_image = True
                log_and_print("debug", "Docker image {} found and will not be downloaded.".format(image_name))
                break
        if not found_image:
            # We don't have the image and --pull "missing"
            try:
                dc.api.pull(image_name)
            except docker.errors.APIError as e:
                log_and_print("error", "{}".format(e.args))
                return False
            else:
                log_and_print("info", "Docker just downloaded image {}.".format(image_name))


def prune_images():
    """
    Prunes untagged images if they are described in config file
    :return: True
    """
    dc = docker.from_env()
    for image in dc.images.list(all=True, filters={'dangling': True}):
        for key, value in config["images"].items():
            if image.attrs['RepoDigests'][0].split("@")[0] in value:
                try:
                    dc.images.remove(image.id)
                except docker.errors.ContainerError as e:
                    log_and_print("error", "{}".format(e.stderr))
                except docker.errors.ImageNotFound as e:
                    log_and_print("error", "{}".format(e.args))
                else:
                    # images.remove() does not return anything
                    log_and_print("debug", "Removed {}, image.short_id={}"
                                  .format(image.attrs['Config']['Image'], image.short_id))


def prune_containers():
    """
    Prunes containers if they were run using Docker module.
    :return: True
    """
    filters = []
    for scanner in config["scanners"]:
        filters.append({'status': 'exited', 'ancestor': config["scanners"][scanner]["image"].split(":")[0]})

    dc = docker.from_env()

    for filter_dict in filters:
        for container in dc.containers.list(all=True, filters=filter_dict):
            try:
                container.remove()
            except docker.errors.ContainerError as e:
                log_and_print("error", "{}".format(e.stderr))
            else:
                # container.remove() does not return anything
                log_and_print("debug", "Removed {}, container.short_id={}"
                              .format(container.attrs['Config']['Image'], container.short_id))


def clean_up():
    """
    Removes Git cloned repos and Docker images.
    Called by main().
    :return: True in case of success; exits with error code if failed to remove Goats
    """
    import shutil

    if not args.cleanup and not args.onlyCleanup:
        return

    log_and_print("info", "Starting clean up...")

    dc = docker.from_env()

    # Remove Docker images: $ docker rmi [image]
    # There shall be containers to be pruned because I can't use flag remove=True using create_container() function
    for scanner in config["scanners"]:
        try:
            dc.images.remove(config["scanners"][scanner]["image"].split(":")[0])

        except docker.errors.ImageNotFound as e:
            # The image should be there.
            log_and_print("error", "{}".format(e.args))

        except docker.errors.ContainerError:
            log_and_print("error", "Error: Could not remove Docker image {}.".format(
                config["scanners"][scanner]["image"].split(":")[0]
            ))

    # Remove goat clones (only dest_clones/results folder will remain):
    if not args.source:
        json_goats = get_goats(goats_file)
        for target in json_goats["targets"]:
            # This will remove directories; the reason for having running_as_root()
            target_dir = dest_clones + "/" + target["local_folder"]
            if os.path.isdir(target_dir):
                # We know the directory is there
                try:
                    shutil.rmtree(target_dir)
                except PermissionError:
                    dest_not_writable(target_dir)
                else:
                    log_and_print("debug", "Directory {} was removed.".format(target_dir))

    # Do not send this message to log
    args.verbose and print("Done.\n")
    return True  # Do not remove


def get_goats(goats):
    """
    Reads goats file specified in milking_goat.json (default: goats.json) into a JSON object
    Called by clone_goats(), run_scan(), create_json_structure() and clean_up()
    :param goats: Filename
    :return: True if successfully loaded the file; False in case of exception
    """
    try:
        return load_from_json(goats)
    except (FileNotFoundError, PermissionError):
        return False


def log_and_print(msg_loglevel, message):
    """
    Logs a message to stdout and/ot file
    :param msg_loglevel: Log level defined for that message
    :param message: The message itself
    :return: True
    """
    # Log levels to output to stdout and to logfile
    switch = {
        "debug": 0,
        "info": 1,
        "warn": 2,
        "error": 3,
        "critical": 4
    }
    # Print to stdout: if message loglevel is not debug
    switch.get(msg_loglevel) > 0 and verbose_mode and print(message)

    # Print to log: if message loglevel is in the range configured to be reported:
    if switch.get(msg_loglevel) >= switch.get(log_level, 1):
        logging_enabled and write_to_log(msg_level=msg_loglevel, log_dest=log_output, message_to_log=message)


def write_to_log(msg_level, log_dest, message_to_log):
    """
    Writes JSON dict to file.
    Called by main().
    :param msg_level: Log level before the message
    :param log_dest: Destination where data will be written
    :param message_to_log: Text to be logged
    :return: True for success, otherwise exits with error code in case of exception
    """
    log_datetime = str(datetime.datetime.now().strftime(log_datetime_format))
    try:
        # Creates recursive path if it doesn't exist (should have been created by start_logging()
        Path(results_destination).mkdir(parents=True, exist_ok=True)
        with open(log_dest, 'a') as f:
            # If a message_to_log comes with a '\n' at the end
            message_to_log = message_to_log.strip('\n')
            if not logging_as_json:
                full_msg = str(log_datetime + log_sep + msg_level + log_sep + message_to_log + '\n')
                f.write(full_msg)
            else:
                full_msg = {
                    "datetime": str(log_datetime),
                    "level": str(msg_level),
                    "message": str(message_to_log)
                }
                f.write(json.dumps(full_msg) + "\n")
    except PermissionError:
        dest_not_writable(log_dest)


def prepare_signal_stats(json_object):
    """
    Reads vulnerability numbers from statistics to format a JSON that will be used to choose exit signals
    :param json_object: JSON containing all reports
    :return: JSON dict with number of vulnerabilities by severity
    """
    int_high, int_medium, int_low = 0, 0, 0
    for target in json_object:
        if target == "milking_the_goat":
            continue
        try:
            for scanner in json_object[target]:
                mylist = [x for x in config["scanners"]]
                if scanner not in mylist:
                    continue
                try:
                    int_high += int(json_object[target][scanner]["failed_by_severity"]["high"])
                    int_medium += int(json_object[target][scanner]["failed_by_severity"]["medium"])
                    int_low += int(json_object[target][scanner]["failed_by_severity"]["low"])
                except (KeyError or TypeError):
                    # Could not find "failed_by_severity" key
                    pass
        except (KeyError or TypeError):
            pass

    signal_stats = {
        "high": int_high,
        "medium": int_medium,
        "low": int_low
    }

    return signal_stats


def choose_exit_signal(json_object):
    """
    Chooses the exit signal when used in CI.
    Makes more sense when only one image is assessed in each run, because many images may be assessed but
    only one signal will be returned.
    :param json_object: JSON object containing the summary for each target image
    :return: exit signal, depending on config and vulnerabilities found
    """
    int_high = json_object["high"]
    int_medium = json_object["medium"]
    int_low = json_object["low"]

    log_and_print("debug", "Found: {} high, {} medium and {} low vulnerabilities."
                  .format(int_high, int_medium, int_low))
    if bool_fail_on_high and (int_high > 0):
        log_and_print("debug", "Exiting with signal EXIT_FAIL_HIGH: {}".format(EXIT_FAIL_HIGH))
        sys.exit(EXIT_FAIL_HIGH)
    elif bool_fail_on_medium and (int_high > 0 or int_medium > 0):
        log_and_print("debug", "Exiting with signal EXIT_FAIL_MEDIUM: {}".format(EXIT_FAIL_MEDIUM))
        sys.exit(EXIT_FAIL_MEDIUM)
    elif bool_fail_on_low and (int_high > 0 or int_medium > 0 or int_low > 0):
        log_and_print("debug", "Exiting with signal EXIT_FAIL_LOW: {}".format(EXIT_FAIL_LOW))
        sys.exit(EXIT_FAIL_LOW)

    log_and_print("debug", "Exiting with signal EXIT_OK: {}".format(EXIT_OK))
    sys.exit(EXIT_OK)


def start_logging(log_dest):
    """
    Removes and recreates logfile, according to config
    :param log_dest: Full path to log file
    :return: True if successful, otherwise exits with error signal
    """
    try:
        if logging_overwrite_file_if_exists:
            os.remove(log_dest)
        Path(log_dest).touch(exist_ok=True)
    except FileNotFoundError:
        Path(results_destination).mkdir(parents=True, exist_ok=True)
        Path(log_dest).touch(exist_ok=True)
    except PermissionError:
        dest_not_writable(log_dest)


def main():
    start_logging(log_dest=log_output)
    sanity_checks()
    create_json_structure()
    run_scan()
    write_json_to_file(json_milk, results_filename)
    prune_containers()
    prune_images()
    clean_up()
    choose_exit_signal(prepare_signal_stats(json_milk))


# Main scope: Argument Parser
parser = argparse.ArgumentParser()
target_group = parser.add_mutually_exclusive_group()
target_group.add_argument("-s", "--source", help="Run against a source directory", dest='source')
target_group.add_argument("-g", "--goats", help="Run against the Goat pack (default)", dest='goats',
                          action='store_true', default=True)
target_group.add_argument("-l", "--locals", help="Run against a list of local projects", dest='locals',
                          action='store_true')
parser.add_argument("--version", help="Print current version and exit", dest='version', action='store_true')
parser.add_argument("-f", "--config", help="Config file", dest='config', default="milking_goat.json")
parser.add_argument("-k", "--skip-kics", help="Skip KICS execution", dest='skipKics', action='store_true')
parser.add_argument("-c", "--skip-checkov", help="Skip Checkov execution", dest='skipCheckov', action='store_true')
parser.add_argument("-t", "--skip-tfsec", help="Skip tfsec execution", dest='skipTfsec', action='store_true')
parser.add_argument("-e", "--skip-terrascan", help="Skip Terrascan execution", dest='skipTerrascan',
                    action='store_true')
parser.add_argument("-y", "--skip-trivy", help="Skip Trivy execution", dest='skipTrivy', action='store_true')
parser.add_argument("--force-docker-pull", help="Make Docker pull the image on every run",
                    dest='forceDockerPull', action='store_true')
parser.add_argument("-v", "--verbose", help="Verbose mode", dest='verbose', action='store_true')
parser.add_argument("-o", "--output", help="Override output_folder parameter in config file", dest='output')
parser.add_argument("-i", "--ignore-root", help="Ignore being executed as root", dest='ignoreRoot', action='store_true')
parser.add_argument("-x", "--cleanup", help="Enable clean up after execution", dest='cleanup', action='store_true')
parser.add_argument("--only-cleanup", help="Execute a clean up and exit", dest='onlyCleanup', action='store_true')

args = parser.parse_args()

# Main scope: config file
try:
    config = load_from_json(args.config)
    # Scanners, Image
    docker_image_checkov = config["scanners"]["checkov"]["image"]
    docker_image_tfsec = config["scanners"]["tfsec"]["image"]
    docker_image_kics = config["scanners"]["kics"]["image"]
    docker_image_terrascan = config["scanners"]["terrascan"]["image"]
    docker_image_trivy = config["scanners"]["trivy"]["image"]
    # Scanners, Output format
    output_format_checkov = config["scanners"]["checkov"]["output_format"]
    output_format_tfsec = config["scanners"]["tfsec"]["output_format"]
    output_format_kics = config["scanners"]["kics"]["output_format"]
    output_format_terrascan = config["scanners"]["terrascan"]["output_format"]
    output_format_trivy = config["scanners"]["trivy"]["output_format"]
    # Scanners, Output filename
    results_checkov_filename = config["scanners"]["checkov"]["output_filename"]
    results_tfsec_filename = config["scanners"]["tfsec"]["output_filename"]
    results_kics_filename = config["scanners"]["kics"]["output_filename"]
    results_terrascan_filename = config["scanners"]["terrascan"]["output_filename"]
    results_trivy_filename = config["scanners"]["trivy"]["output_filename"]
    # Input, Sources
    goats_file = config["input"]["goats_source"]
    local_file = config["input"]["local_source"]
    # Output, Destinations
    dest_clones = config["output"]["clones_destination"]
    results_destination = config["output"]["results_destination"]
    goats_destination = config["output"]["goats_destination"]
    results_filename = config["output"]["results_filename"]
    bool_command_line_args = config["output"]["command_line_args"]
    bool_docker_version = config["output"]["docker_version"]
    # Logging
    verbose_mode = config["logging"]["verbose_stdout"]
    logging_enabled = config["logging"]["logging_enabled"]
    logging_as_json = config["logging"]["logging_as_json"]
    logging_overwrite_file_if_exists = config["logging"]["logging_overwrite_file_if_exists"]
    log_level = config["logging"]["logging_level"]
    log_output = config["logging"]["logging_file"]
    log_sep = config["logging"]["logging_separator"]
    log_datetime_format = config["logging"]["logging_datetime_format"]
    # Settings
    bool_ignore_running_as_root = config["settings"]["ignore_running_as_root"]
    # CI, fail on findings
    bool_fail_on_high = config["ci"]["fail_on_findings"]["fail_on_high"]
    bool_fail_on_medium = config["ci"]["fail_on_findings"]["fail_on_medium"]
    bool_fail_on_low = config["ci"]["fail_on_findings"]["fail_on_low"]
    # CI, exit signals
    EXIT_OK = int(config["ci"]["exit_signals"]["exit_ok"])
    EXIT_FAIL_LOW = int(config["ci"]["exit_signals"]["exit_fail_low"])
    EXIT_FAIL_MEDIUM = int(config["ci"]["exit_signals"]["exit_fail_medium"])
    EXIT_FAIL_HIGH = int(config["ci"]["exit_signals"]["exit_fail_high"])

    # About output formats:
    # https://github.com/bridgecrewio/checkov/blob/master/docs/2.Basics/Reviewing%20Scan%20Results.md
    # https://aquasecurity.github.io/tfsec/v1.0.11/getting-started/usage/
    # https://github.com/Checkmarx/kics/blob/master/docs/results.md
    # https://runterrascan.io/docs/usage/command_line_mode/#configuring-the-output-format-for-a-scan

    # Variables declared in main scope
    results_checkov = ""
    results_tfsec = ""
    results_kics = ""
    results_terrascan = ""
    results_trivy = ""

    # Overrides sinker_output_folder from config file
    if args.output:
        results_destination = args.output

    # Overrides ignore_running_as_root from config file
    if args.ignoreRoot:
        bool_ignore_running_as_root = True

    # Overrides verbose_mode from config file
    if args.verbose:
        verbose_mode = True

    # Main JSON for the app
    json_milk = {}

except (PermissionError, FileNotFoundError):
    missing_config(args.config)

else:
    # clean_up() depends on config[] and config section above depends on ArgParser (defined before)
    args.version and print_version() and sys.exit(EXIT_OK)
    args.onlyCleanup and clean_up() and sys.exit(EXIT_OK)

if __name__ == "__main__":
    main()
