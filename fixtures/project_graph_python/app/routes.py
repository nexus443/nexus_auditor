from fastapi import FastAPI

from .dynamic import dispatch
from .sanitized import safe_execute
from .services import execute_command

app = FastAPI()


@app.post("/run")
def run_command(user_input: str):
    return execute_command(user_input)


@app.post("/safe-run")
def run_safe(user_input: str):
    return safe_execute(user_input)


@app.post("/dispatch/{handler}")
def run_dynamic(handler: str, payload: str):
    return dispatch(handler, payload)
