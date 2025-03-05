#!/usr/bin/env python3
import requests
import sys
import csv
import tempfile
import os
import concurrent.futures
from multiprocessing import Process, Queue
from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings


# --- CONFIGURATION ---
GITHUB_TOKEN = "YOURPAT"
GITHUB_ORG = "YOURORG"
INPUT_CSV_FILE = "users.csv"  # Input CSV file (first column contains usernames)
OUTPUT_CSV_FILE = "master_repos.csv"  # Output CSV file that will list all public repos for each user
RESULTS_CSV_FILE = "scan_results.csv"  # CSV file to store the scan results

# Prevent Git from prompting for credentials.
os.environ["GIT_TERMINAL_PROMPT"] = "0"
os.environ["GIT_ASKPASS"] = "echo"

HEADERS = {
    "Accept": "application/vnd.github+json",
    "Authorization": f"Bearer {GITHUB_TOKEN}",
}

def get_user_repos(username: str, auth_headers: dict) -> list:
    """
    Retrieve public repositories for a given user, using pagination.
    """
    repos = []
    page = 1
    while True:
        url = f"https://api.github.com/users/{username}/repos?per_page=100&page={page}"
        resp = requests.get(url, headers=HEADERS)
        if resp.status_code != 200:
            print(f"Error fetching repos for {username}: {resp.json()}")
            break
        page_data = resp.json()
        if not page_data:
            break
        repos.extend(page_data)
        page += 1
    return repos



def get_org_members(org: str) -> list:
    """Retrieve all members of the specified organization."""
    members = []
    page = 1
    while True:
        url = f"https://api.github.com/orgs/{org}/members?per_page=100&page={page}"
        resp = requests.get(url, headers=HEADERS)
        if resp.status_code != 200:
            print("Error fetching organization members:", resp.json())
            sys.exit(1)
        page_data = resp.json()
        if not page_data:
            break
        members.extend(page_data)
        page += 1
    return members

def write_repos_to_csv(repos_data: list, output_csv: str):
    """
    Writes a list of repository data to a CSV file.
    Each item in repos_data should be a dict with keys: username, repo_name, repo_full_name, html_url, description.
    """
    fieldnames = ["username", "repo_name", "repo_full_name", "html_url", "description"]
    try:
        with open(output_csv, "w", newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in repos_data:
                writer.writerow(row)
    except Exception as e:
        print(f"Error writing to CSV file '{output_csv}': {e}")
        sys.exit(1)


def scan_repo_for_secrets(repo_url):
    with tempfile.TemporaryDirectory() as tmpdirname:
        try:
            clone_repo(repo_url, tmpdirname)
        except Exception:
            return {"error": f"Failed to clone {repo_url}"}
        # findings = scan_directory(tmpdirname)
        findings = scan_directory_concurrent(tmpdirname)
        return findings

def clone_repo(repo_url, clone_to_dir):
    repo_url = transform_repo_url(repo_url)
    print(f"Cloning {repo_url} into {clone_to_dir}")
    try:
        from git import Repo
        Repo.clone_from(
            repo_url,
            clone_to_dir,
            multi_options=["--config", "credential.helper="],
            allow_unsafe_options=True  # Allow the use of --config
        )
    except Exception as e:
        print(f"Error cloning {repo_url}: {e}")
        raise
    print(f"Successfully cloned {repo_url}")

def transform_repo_url(repo_url: str) -> str:
    """
    Convert SSH URLs to HTTPS URLs for GitHub, ensure the URL ends with '.git',
    and embed a dummy token to avoid authentication prompts.
    """
    if repo_url.startswith("git@github.com:"):
        repo_url = repo_url.replace("git@github.com:", "https://github.com/")
    # If it's an HTTPS URL and does not end with '.git', append it.
    if repo_url.startswith("https://github.com/") and not repo_url.endswith(".git"):
        repo_url += ".git"
    # Embed a dummy token to bypass authentication prompts.
    if repo_url.startswith("https://github.com/"):
        repo_url = repo_url.replace("https://", "https://x-access-token:@")
    return repo_url

def scan_file_worker(file_path, queue):
    """
    Worker function that scans a file for secrets and puts the JSON result in a queue.
    """
    secrets = SecretsCollection()
    with default_settings():
        secrets.scan_file(file_path)
    # Put the result (a JSON string or a dict) into the queue.
    queue.put(secrets.json())

def scan_file_worker_concurrent(file_path):
    """
    Worker function that scans a file for secrets and returns a tuple of (file_path, result).
    """
    secrets = SecretsCollection()
    with default_settings():
        secrets.scan_file(file_path)
    return file_path, secrets.json()

def scan_file_with_timeout(file_path, timeout=100):
    """
    Scans a single file using a separate process.
    If the scan does not complete within 'timeout' seconds, the process is terminated.
    Returns the scan result (as returned by secrets.json()) or a timeout error.
    """
    queue = Queue()
    p = Process(target=scan_file_worker, args=(file_path, queue))
    p.start()
    p.join(timeout)
    if p.is_alive():
        # If still running after timeout, terminate it.
        p.terminate()
        p.join()
        print(f"Timeout scanning {file_path}")
        return {"error": "timeout"}
    # If the worker finished, retrieve the result.
    if not queue.empty():
        return queue.get()
    return {}

def scan_directory(directory, timeout=100):
    """
    Walk through the given directory and scan each file for secrets.
    If scanning a file takes longer than 'timeout' seconds, it is skipped.
    Returns a dictionary mapping file paths to scan results.
    """
    findings = {}
    for root, _, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            result = scan_file_with_timeout(file_path, timeout)
            print(f"Finished Scanning File: {file_path}")
            if result:  # only record if result is not empty
                findings[file_path] = result
    return findings


def scan_directory_concurrent(directory, timeout=100, max_workers=None):
    """
    Collects all file paths in the directory and scans them concurrently using a process pool.
    If scanning a file takes longer than `timeout` seconds, it is skipped.

    Parameters:
        directory (str): The directory to scan.
        timeout (int): Per-file timeout in seconds.
        max_workers (int): Maximum number of worker processes (default: os.cpu_count()).

    Returns:
        findings (dict): A dictionary mapping file paths to scan results.
    """
    # Collect all file paths to scan.
    file_paths = []
    for root, _, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            file_paths.append(file_path)

    findings = {}
    # Use a process pool to scan files concurrently.
    with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
        # Submit all files to the executor.
        future_to_file = {executor.submit(scan_file_worker_concurrent, fp): fp for fp in file_paths}

        # Process results as they complete.
        for future in concurrent.futures.as_completed(future_to_file):
            file_path = future_to_file[future]
            try:
                fp, result = future.result(timeout=timeout)
                if result:
                    findings[fp] = result
            except concurrent.futures.TimeoutError:
                print(f"Timeout scanning {file_path}")
            except Exception as e:
                print(f"Error scanning {file_path}: {e}")
    return findings

def write_scan_results_to_csv(results: list, output_csv: str):
    fieldnames = ["user", "repo_url", "file", "type", "line_number", "hashed_secret", "is_verified"]
    try:
        with open(output_csv, "w", newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for result in results:
                writer.writerow(result)
    except Exception as e:
        print(f"Error writing to CSV file '{output_csv}': {e}")

def main():

    # Step 3: Read usernames from the input CSV file.
    users = get_org_members(GITHUB_ORG)
    print(f"Found {len(users)} usernames.")

    # Step 4: For each username, fetch public repositories.
    master_repos = []
    master_results = []
    for user in users:
        username = user['login']
        print(f"Fetching repos for user: {username}")
        repos = get_user_repos(username, HEADERS)
        print(f"  Found {len(repos)} repos for user '{username}'.")
        for repo in repos:
            repo_info = {
                "username": username,
                "repo_name": repo.get("name", ""),
                "repo_full_name": repo.get("full_name", ""),
                "html_url": repo.get("html_url", ""),
                "description": repo.get("description", "")
            }
            master_repos.append(repo_info)
            findings = scan_repo_for_secrets(repo.get("html_url", ""))
            if findings:
                for finding in findings:
                    if finding in findings and finding in findings[finding]:
                        full_list = findings[finding][finding]
                        for match in full_list:
                            master_results.append({
                                "user": username,
                                "repo_url": repo.get("html_url", ""),
                                "file": finding,
                                "type": match["type"],
                                "line_number": match["line_number"],
                                "hashed_secret": match["hashed_secret"],
                                "is_verified": match["is_verified"]
                            })
                    else:
                        print()

    # Step 5: Write all repository information to the master CSV file.
    write_repos_to_csv(master_repos, OUTPUT_CSV_FILE)
    print(f"Master CSV file '{OUTPUT_CSV_FILE}' created with {len(master_repos)} repo entries.")

    write_scan_results_to_csv(master_results, RESULTS_CSV_FILE)
    print(f"\nMaster CSV file '{RESULTS_CSV_FILE}' created with scan results for {len(master_results)} repositories.")


if __name__ == "__main__":
    main()
