import shlex
import subprocess


def safe_execute(user_input: str):
    safe_value = shlex.quote(user_input)
    return subprocess.run(["printf", "%s", safe_value], shell=False, check=False)
