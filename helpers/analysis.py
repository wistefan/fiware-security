import sys
from json import load
import matplotlib.pyplot as plt
import pandas as pd
from fabric import Connection
from pathlib import Path


def hist_data(data, version, basename, name):
    filename = basename + '_v' + version + '.png'

    if version == '2':
        key_version = 'cvss_v2'
        title = name + ' CVSS v2 Vulnerabilities'
        y_axis_title = '# CVSS v2'
    elif version == '3':
        key_version = 'cvss_v3'
        title = name + ' CVSS v3 Vulnerabilities'
        y_axis_title = '# CVSS v3'
    else:
        raise Exception(f"version have to be 2 or 3, current value {version}")

    # Extract the relevant data
    new_data = [x['nvd_data'][0][key_version]['base_score'] for x in data]

    # Convert list to DataFrame
    df = pd.DataFrame(new_data, columns=['score'])

    # Generate the Histogram
    plt.xlabel('Base Scores')
    plt.ylabel(y_axis_title)
    plt.title(title)
    plt.hist(df['score'], bins=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10], color='blue', edgecolor='black')

    # Fix grid
    plt.xlim(0, 10)

    plt.grid(True, which='both', linestyle='--')
    plt.show()
    plt.close()

    plt.savefig(filename, bbox_inches='tight')


def print_data(issue, version):
    print(f"NVD ID: {issue['nvd_data'][0]['id']}")
    print(f"Package Name: {issue['package_name']}")
    print(f"Package Version: {issue['package_version']}")
    print(f"Base Score: {issue['nvd_data'][0][version]['base_score']}")
    print(f"Exploitability Score: {issue['nvd_data'][0][version]['exploitability_score']}")
    print(f"Impact Score: {issue['nvd_data'][0][version]['impact_score']}")
    print(f"Severity: {issue['severity']}\n")


def problematic_issues(data, version):
    if version == '2':
        key_version = 'cvss_v2'
        print_version = 'CVSS v2'
    elif version == '3':
        key_version = 'cvss_v3'
        print_version = 'CVSS v3'
    else:
        raise Exception(f"version have to be 2 or 3, current value {version}")

    big_problem = [x for x in data if x['nvd_data'][0][key_version]['base_score'] > 9]

    print(f"Number of vulnerabilities with {print_version} Base Score > 9: {len(big_problem)}")

    # Print the information of the identified issue
    [print_data(issue=x, version=key_version) for x in big_problem]


def open_file(file):
    with open(file) as f:
        file_data = load(f)

    return file_data


def get_file(args):
    """
    :param args:
    :return:
    """
    if len(args) == 2:
        basename = args[1]
        name = args[1].split('-')[0]

        file_data = open_file(args[1])

        return basename, name, file_data
    elif len(args) == 1:
        # Get the list of last reports from the machine
        # find /home/ubuntu/security-scan/anchore -iname "*.json" -mtime -20 -print  -> list of files to copy
        c = Connection(
            host="46.17.108.117",
            user="ubuntu",
            connect_kwargs={
                "key_filename": "/Users/fernandolopez/Documents/workspace/security/fiware-security/deploy/ansible/keypair",
            },
        )

        result = c.run('find /home/ubuntu/security-scan/anchore -iname "*.json" -mtime -20 -print | sort')

        files = result.stdout.split("\n")[:-1]
        [c.get(file) for file in files]

        basename = [Path(file).name for file in files]
        name = [x.split('-')[0] for x in basename]

        file_data = [open_file(x) for x in basename]

        return basename, name, file_data
    else:
        raise Exception("It is mandatory to introduce the report file to make the analysis")


def analyse_data(basename, name, content):
    print(f'\n\nSummary of vulnerabilities of {name}')
    print(f"Number of vulnerabilities: {len(content['vulnerabilities'])}")

    # There is some vulnerabilities with no NVD Data -> Dismiss them, they have been identified by
    # Vendor with very low score
    ohne_nvd = [x for x in content['vulnerabilities'] if len(x['nvd_data']) == 0]
    mit_nvd = [x for x in content['vulnerabilities'] if len(x['nvd_data']) != 0]

    print(f"Number of vulnerabilities without NVD Data: {len(ohne_nvd)}")
    print(f"Number of vulnerabilities with NVD Data: {len(mit_nvd)}")

    hist_data(data=mit_nvd, version='2', basename=basename, name=name)
    hist_data(data=mit_nvd, version='3', basename=basename, name=name)

    problematic_issues(data=mit_nvd, version='2')
    problematic_issues(data=mit_nvd, version='3')


if __name__ == '__main__':
    basename, name, content = get_file(sys.argv)

    if isinstance(basename, str):
        analyse_data(basename=basename, name=name, content=content)
    else:
        # There is a list of files to analyse
        for i in range(0, len(basename)):
            analyse_data(basename=basename[i], name=name[i], content=content[i])
