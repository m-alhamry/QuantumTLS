import subprocess
import os
import logging
import sys
from pathlib import Path

# Configuration
REPO_PATH = r"C:\Shared\githup_project\QuantumTLS"  # Path to QuantumTLS repository
REMOTE_NAME = "origin"  # Git remote name
BRANCH_NAME = "main"  # Branch to push to
LOG_FILE = "git_automate.log"  # Log file
LOGS_DIR = "logs"  # Logs directory relative to REPO_PATH
GITKEEP_FILE = os.path.join(LOGS_DIR, ".gitkeep")  # Path to .gitkeep

def setup_logging():
    """Configure logging to file and console."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger("git_automate")

def run_git_command(args, cwd, check=True):
    """Execute a Git command and return its output."""
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=check
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if check:
            logging.error(f"Git command '{' '.join(args)}' failed: {e.stderr}")
            raise RuntimeError(f"Git command failed: {e.stderr}")
        return e.stdout.strip() + e.stderr.strip()
    except FileNotFoundError:
        logging.error("Git is not installed or not found in PATH.")
        raise RuntimeError("Git is not installed or not found in PATH.")

def check_git_repo(cwd):
    """Verify that the directory is a Git repository."""
    try:
        run_git_command(["rev-parse", "--is-inside-work-tree"], cwd)
        logging.info("Valid Git repository detected.")
    except RuntimeError:
        logging.error(f"{cwd} is not a Git repository.")
        raise RuntimeError(f"{cwd} is not a Git repository.")

def ensure_gitignore(cwd):
    """Ensure .gitignore exists with required exclusions."""
    gitignore_path = os.path.join(cwd, ".gitignore")
    required_content = [
        "git_automate.log",
        "CHANGELOG.md",
        "client.log",
        "server.log",
        "logs/*",
        "!logs/.gitkeep"
    ]
    if not os.path.exists(gitignore_path):
        logging.info("Creating .gitignore file.")
        with open(gitignore_path, "w", encoding="utf-8") as f:
            f.write("\n".join(required_content) + "\n")
    else:
        with open(gitignore_path, "r", encoding="utf-8") as f:
            content = f.read().splitlines()
        missing = [line for line in required_content if line not in content]
        if missing:
            logging.info(f"Appending missing entries to .gitignore: {missing}")
            with open(gitignore_path, "a", encoding="utf-8") as f:
                f.write("\n" + "\n".join(missing) + "\n")

def ensure_gitkeep(cwd):
    """Ensure .gitkeep exists in the logs directory."""
    logs_path = os.path.join(cwd, LOGS_DIR)
    gitkeep_path = os.path.join(cwd, GITKEEP_FILE)
    if not os.path.exists(logs_path):
        logging.info(f"Creating logs directory: {logs_path}")
        os.makedirs(logs_path)
    if not os.path.exists(gitkeep_path):
        logging.info(f"Creating .gitkeep in {LOGS_DIR}")
        with open(gitkeep_path, "w", encoding="utf-8") as f:
            f.write("")  # Empty file
        run_git_command(["add", GITKEEP_FILE], cwd)
        logging.info(f"Added {GITKEEP_FILE} to Git.")

def untrack_ignored_files(cwd):
    """Remove tracked files that are listed in .gitignore."""
    # Get list of tracked files
    logging.info("Here1")
    tracked_files = run_git_command(["ls-files"], cwd).splitlines()
    if not tracked_files:
        logging.info("No tracked files to check.")
        return False

    # Check which tracked files are ignored
    ignored_tracked = []
    for file in tracked_files:
        logging.info("Here2")
        status = run_git_command(["check-ignore", file], cwd, check=False)
        if status and file != GITKEEP_FILE:  # Exclude .gitkeep
            ignored_tracked.append(file)

    if not ignored_tracked:
        logging.info("No tracked files are ignored by .gitignore.")
        return False

    # Untrack ignored files
    logging.info(f"Untracking ignored files: {ignored_tracked}")
    run_git_command(["rm", "--cached"] + ignored_tracked, cwd)
    run_git_command(["commit", "-m", "Remove tracked files listed in .gitignore"], cwd)
    logging.info("Committed removal of ignored tracked files.")
    return True

def get_git_status(cwd):
    """Get and display the current Git status."""
    status = run_git_command(["status", "--short"], cwd)
    if status:
        logging.info("Git status:\n" + status)
        return status.splitlines()
    else:
        logging.info("No changes detected in the repository.")
        return []

def add_files(cwd, all_files=False, specific_files=None):
    """Add files to the Git staging area, respecting .gitignore."""
    ensure_gitkeep(cwd)  # Ensure .gitkeep exists
    if all_files:
        logging.info("Adding all modified files (respecting .gitignore).")
        run_git_command(["add", "."], cwd)
        return True
    elif specific_files:
        added = False
        for file in specific_files:
            file_path = os.path.join(cwd, file)
            if not os.path.exists(file_path):
                logging.warning(f"File {file} does not exist, skipping.")
                continue
            # Check if file is ignored
            status = run_git_command(["check-ignore", file], cwd, check=False)
            if status:
                logging.warning(f"File {file} is ignored by .gitignore, skipping.")
                continue
            logging.info(f"Adding file: {file}")
            run_git_command(["add", file], cwd)
            added = True
        return added
    else:
        logging.info("No files specified to add.")
        return False

def commit_changes(cwd, message):
    """Commit staged changes with the provided message."""
    logging.info(f"Committing changes with message: {message}")
    run_git_command(["commit", "-m", message], cwd)
    logging.info("Changes committed successfully.")

def push_changes(cwd, remote, branch):
    """Push committed changes to the remote branch."""
    logging.info(f"Pushing changes to {remote}/{branch}.")
    run_git_command(["push", remote, branch], cwd)
    logging.info(f"Successfully pushed to {remote}/{branch}.")

def main():
    logger = setup_logging()
    cwd = Path(REPO_PATH).resolve()

    try:
        # Verify repository
        logger.info(f"Checking repository at {cwd}")
        check_git_repo(cwd)

        # Ensure .gitignore and .gitkeep
        ensure_gitignore(cwd)

        # Untrack any ignored files that are currently tracked
        # untrack_ignored_files(cwd)

        # Get and display Git status
        status_lines = get_git_status(cwd)
        if not status_lines:
            logger.info("No changes to commit. Exiting.")
            return

        # Prompt user to choose files to add
        print("\nChanged files:")
        for i, line in enumerate(status_lines, 1):
            print(f"{i}. {line}")
        choice = input("\nAdd all files? (y/n): ").strip().lower()

        added = False
        if choice == "y":
            added = add_files(cwd, all_files=True)
        else:
            files = []
            while True:
                file_input = input("Enter file path to add (or press Enter to finish): ").strip()
                if not file_input:
                    break
                files.append(file_input)
            if files:
                added = add_files(cwd, specific_files=files)

        if not added:
            logger.info("No files were added. Exiting.")
            return

        # Prompt for commit message
        commit_message = input("Enter commit message (or press Enter for default): ").strip()
        if not commit_message:
            commit_message = "Update QuantumTLS project"
        commit_changes(cwd, commit_message)

        # Push changes
        push_changes(cwd, REMOTE_NAME, BRANCH_NAME)

    except RuntimeError as e:
        logger.error(f"Script failed: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Script interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()