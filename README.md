# Milking the Goat :goat:

Milking the Goat is a Python script to automate:
- Infrastructure as Code (IaC) security tools benchmarking;
- execution of multiple tools on a single project.

## Why?

- Running these tools manually can be boring and time-consuming when there are multiple projects
- Which (free) IaC security tool is best for a given project?
- Can we improve IaC security combining multiple free tools?

## Target audience

- Users looking to automate IaC security tools
- Users looking to benchmark free IaC security tools

## Pre-requisites

- Python 3 (tested with version 3.8)
- GitPython module (tested with version 3.1.27)
- Docker Engine (tested with version 20.10.12)
- Docker module for Python (tested with version 5.0.3)

## Goats

Goats are vulnerable apps/installations/code purposefully created this way for testing and learning. These Goats are free and open-source. Check their websites to learn their differences.

- [TerraGoat](https://github.com/bridgecrewio/terragoat)
- [CfnGoat](https://github.com/bridgecrewio/cfngoat)
- [KustomizeGoat](https://github.com/bridgecrewio/kustomizegoat)
- [KaiMonkey](https://github.com/accurics/KaiMonkey)
- [SadCloud](https://github.com/nccgroup/sadcloud)
- [KubernetesGoat](https://github.com/madhuakula/kubernetes-goat)

Do you like Goats? Check these out:

- [CDKGoat](https://github.com/bridgecrewio/cdkgoat)
- [WrongSecrets](https://github.com/commjoen/wrongsecrets)

## IaC Security Tools

The tools automated here don't have the same features. Some might support different IaC formats, others only Terraform code. Check their websites to learn the differences between their latest versions.

- [Checkov](https://www.checkov.io/)
- [tfsec](https://info.aquasec.com/tfsec)
- [KICS](https://checkmarx.com/product/opensource/kics-open-source-infrastructure-as-code-project/)
- [Terrascan](https://runterrascan.io/)
- [Trivy](https://aquasecurity.github.io/trivy/latest/misconfiguration/iac/)

> Note:
> - Bridgecrew, creator of Checkov, also created the Goats TerraGoat, CfnGoat and KustomizeGoat
> - Accurics, creator of Terrascan, also created Goat KaiMonkey
> - tfsec and Trivy belong to the same vendor, Aqua

### Tested Versions

- Checkov v2.0.910
- tfsec v1.4.2
- KICS v1.5.2
- Terrascan v1.13.2
- Trivy v0.24.1

## Execution

1. Clone this repo (`git clone https://github.com/mmartins000/milkingthegoat.git`)
2. Change directory there with `cd milkingthegoat`
3. Run `pip install -r requirements.txt`
4. Run `python3 milking_goat.py -h` to check the options
5. Run `python3 milking_goat.py -v` to run in verbose mode
6. Compare the results of the tools (check `milking_goat.json` for the location of results files).

### Under the Hood

Milking the Goat will:
1. Clone Goats' repos (if no local project or list is specified)
2. Download Docker images for the scanning tools
3. Run the scanning tools
4. Write a JSON file with the execution summary
5. Clean up (if this option is selected)

## Configuration

Check and edit the default config file `milking_goat.json` or create your own.

### Your own goats

You can edit or replace file `goats.json` for a file that contains a list of your goat projects to assess. You can also use `local.json` to list other projects to assessed.

## Output

Help menu:
```text
$ python3 milking_goat.py -h
usage: milking_goat.py [-h] [-s SOURCE | -g | -l] [--version] [-f CONFIG] [-k] [-c] [-t] [-e] [-y] [--force-docker-pull] [-v] [-i] [-x] [--only-cleanup]

optional arguments:
  -h, --help            show this help message and exit
  -s SOURCE, --source SOURCE
                        Run against a source directory
  -g, --goats           Run against the Goat pack (default)
  -l, --locals          Run against a list of local projects
  --version             Print current version and exit
  -f CONFIG, --config CONFIG
                        Config file
  -k, --skip-kics       Skip KICS execution
  -c, --skip-checkov    Skip Checkov execution
  -t, --skip-tfsec      Skip tfsec execution
  -e, --skip-terrascan  Skip Terrascan execution
  -y, --skip-trivy      Skip Trivy execution
  --force-docker-pull   Make Docker pull the image on every run
  -v, --verbose         Verbose mode
  -i, --ignore-root     Ignore being executed as root
  -x, --cleanup         Enable clean up after execution
  --only-cleanup        Execute a clean up and exit
```

Sample execution with three 'Goats' and Checkov only:
```text
$ python3 milking_goat.py -v -k -e -t
Cloning the Goats in /tmp
Starting IaC code scans...
Running Checkov on /tmp/terragoat...
Docker ran Checkov container in /tmp/terragoat, it took 12.17 secs and the report was saved in /tmp/results/terragoat/results_checkov.json.
Running Checkov on /tmp/cfngoat...
Docker ran Checkov container in /tmp/cfngoat, it took 11.8 secs and the report was saved in /tmp/results/cfngoat/results_checkov.json.
Running Checkov on /tmp/kustomizegoat...
Docker ran Checkov container in /tmp/kustomizegoat, it took 7.54 secs and the report was saved in /tmp/results/kustomizegoat/results_checkov.json.
Finished scanning IaC code.
Milking the Goat JSON saved to /tmp/milking_goat_results/milking_goat_results.json
```
Sample output of command `$ python3 milking_goat.py -v -c -k -e -s /tmp/terragoat`:
```text
{
    "milking_the_goat": {
        "script_version": "0.1",
        "json_version": "1",
        "url": "https://github.com/mmartins000/milkingthegoat",
        "command_line_args": null,
        "docker_version": null,
        "start_time": "2022-02-27 16:22:18",
        "end_time": "2022-02-27 16:22:20",
        "duration": "2 seconds"
    },
    "terragoat": {
        "source": "/tmp/terragoat",
        "tfsec": {
            "json_file": "/tmp/results/terragoat/results_tfsec.json",
            "version": "v1.4.2",
            "running_time": "1.34 seconds",
            "check_type": "terraform",
            "passed": 0,
            "skipped": 0,
            "failed": 255,
            "failed_by_severity": {
                "high": 88,
                "medium": 88,
                "low": 45
            }
        }
    }
}
```

##### Other options
To use a list of goats as targets:
`$ python3 milking_goat.py --goats` (default)

To use a list of local folders as targets and enable verbose mode:
`$ python3 milking_goat.py -v --local`

To use a single local folder as target:
`$ python3 milking_goat.py -s /tmp/terragoat`

## Some things to consider when comparing tools

- Requirements
- Licensing and limitations
- Supported platforms (if live scanning is supported, like AWS, Azure, GCP, etc)
- Integration with CI/CD pipelines
- Ability to automate or run in CLI mode
- Input formats (IaC code like Terraform, Kubernetes, Cloudformation, etc)
- Ability to select policies to run
- Time it takes to run
- Output formats (JSON, YAML, Github, etc)
- Failed checks they were able to catch
